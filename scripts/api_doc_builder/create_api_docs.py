"""
Automatically create API docs when the comments for each method are structured correctly

FAQ:

1. Why is this necessary?

Need to create good documentation on the API. Also good to auto-generate stuff based on the API.

2. What format are the docstrings in?

RST. But I only support a limited portion of rst.

3. Why can't you just write the swagger file manually? Isn't it a pain in the ass to keep this up to date?

Because: (a) shut up (again); (b) it would be nice to automatically generate swagger from the docs to keep the swagger file up to date

4. But doesn't swagger have code generation facilities?

Not for my super custom implementation of Flask. I'm curious what code it can generate though, especially for flask

5. But what if the function docs get out of date?

Then we have bigger issues. Much easier to remember to fix the docs than to fix an external Swagger file

6. Can't I just have a job that kicks off which will remind me to update the swagger file?

Yes. That sounds cool. Let's do that as well.

"""

import ast
# from pprint import pprint
import json
import logging
import os
import re
from argparse import ArgumentParser

import coloredlogs
from bs4 import BeautifulSoup
from rst_utils import parse_rst, get_bullet_list_children, has_child_with_tag

class DocstringParseException(Exception):
    pass


class Function:
    def __init__(self, name):
        self.name = name

        # these are set in the docstring (added later)
        self.about = ""
        # map from argument names to values
        # preserve the order in which they are read
        self.arguments = []
        # map from status codes to their meanings
        self.status_codes = {}
        self.response = []

        # NOTE: this is a bad way to represent routes because methods may not line up between routes
        self.routes = []
        self.http_methods = []
        self.requires_auth = False
        self.requires_csrf_token = False
        self.requires_jwt = False

    def add_argument(self, arg_name, arg_type, is_required):
        assert isinstance(is_required, bool)
        self.arguments.append({
            "name": arg_name,
            "type": arg_type,
            "is_required": is_required
        })

    def set_docstring(self, docstring):
        assert docstring is not None, self.name + " has no docstring"
        # self._parse_docstring_legacy(docstring)
        self._parse_docstring_rst(docstring)
        assert self.about != ""
        if self.status_codes == {}:
            raise DocstringParseException(
                "Expected to find status code list in docstring for function %s" % self.name)
        if self.response == []:
            raise DocstringParseException(
                "Expected to find response in function %s", self.name)

    def _parse_param(self, arg):
        pattern = re.compile(r'(\w+): (\w+) (\(\w+\))?$')
        m = pattern.match(arg)
        try:
            arg_name = m.group(1)
            arg_type = m.group(2)
            is_required = m.group(3) == "(required)"
            return {
                "name": arg_name,
                "type": arg_type,
                "is_required": is_required
            }
        except Exception as e:
            print(pattern)
            print(arg)
            raise e

    def _parse_docstring_rst(self, docstring):
        """
        The response list will contain unparsed RST tags
        """
        doc = parse_rst(docstring)
        for i, section in enumerate(doc.children):
            if i == 0:
                self.about = section.astext()
            elif section.tagname == "section":
                # get the title
                title = [c for c in section.children if c.tagname == "title"][0].astext()
                if title == "Arguments":
                    if has_child_with_tag(section, "bullet_list"):
                        for child in get_bullet_list_children(section):
                            arg = self._parse_param(child.astext())
                            self.add_argument(arg["name"], arg["type"], arg["is_required"])
                elif title == "Status codes":
                    for child in get_bullet_list_children(section):
                        arg = child.astext()
                        head, tail = arg.split(": ", 1)
                        self.status_codes[int(head)] = tail
                elif title == "Response":
                    l = [c for c in section.children if c.tagname != "title"]
                    for child in l:
                        if child.tagname == "paragraph":
                            self.response.append({
                                "type": "text",
                                "val": child.astext()
                            })
                        elif child.tagname == "literal_block":
                            self.response.append({
                                "type": "code",
                                "val": child.astext()
                            })
                        else:
                            print(self.name)
                            print(child)
                            raise Exception
                            #TODO for now
                            self.response.append(child)
                else:
                    raise Exception

 
def parse_child_function(child, api_method_annotation, is_api_method=False, api_doc_annotation=None):
    """Extract all the interesting information from the function.
    All we care about are the decorators, function name, and docstring
    :param is_api_method:           Whether to include this method in documentation
        By default, we figure this out via annotations. Can optionally specify True to bypass this
    :param api_doc_annotation:      Optional. Specify a custom document annotation that allows referencing other docs.
    """
    fn = Function(child.name)
    for decorator in child.decorator_list:
        print(decorator.id)
        if isinstance(decorator, ast.Name):
            # pprint(decorator.id)
            if decorator.id == "requires_json_auth":
                fn.requires_auth = True
            elif decorator.id == "requires_csrf_check":
                fn.requires_csrf_token = True
            elif decorator.id == "jwt_required":
                fn.requires_jwt = True
            elif decorator.id == api_doc_annotation:
                raise AssertionError("doc annotation found")
            else:
                raise Exception("Found unknown decorator name: %s" % decorator.id)
        elif isinstance(decorator, ast.Call):
            if isinstance(decorator.func, ast.Name):
                if decorator.func.id == "requires_json_form_validation":
                    # boring
                    pass
                elif decorator.id == api_doc_annotation:
                    raise AssertionError("doc annotation found")
                else:
                    raise Exception()
            elif isinstance(decorator.func, ast.Attribute):
                if decorator.func.value.id == api_method_annotation:
                    is_api_method = True
                    # OK, it's a function call
                    assert len(decorator.args) == 1
                    # this is the route
                    fn.routes.append(decorator.args[0].s)
                    assert len(decorator.keywords) == 1
                    assert decorator.keywords[0].arg == "methods"
                    # these are the HTTP methods
                    l = decorator.keywords[0].value
                    methods = [x.s for x in l.elts]
                    fn.http_methods = methods
                elif decorator.id == api_doc_annotation:
                    raise AssertionError("doc annotation found")
                else:
                    # this is just a helper method and doesn't need docs
                    logging.debug("function %s is not an API method and will be ignored" % fn.name)
                    return None
            else:
                raise Exception()
        else:
            raise Exception()
    if not is_api_method:
        logging.debug("function %s is not an API method and will be ignored" % fn.name)
        return None
    print(child.__dict__)
    # only expect the functions that are API functions to have correct docs
    # otherwise we should ignore those functions
    fn.set_docstring(ast.get_docstring(child))
    return fn

class ApiParser:
    def __init__(self, fname):
        self.fname = fname
        self.http_verbs = frozenset([
            "get", "post", "patch", "put", "delete"
        ])

    def parse_tree(self, root, api_method_annotation):
        """Look for two kinds of functions:
        - top-level functions with the right API annotation
        - functions on a class
        """
        f1 = self.parse_tree_functions(root, api_method_annotation)
        f2 = self.parse_tree_class(root)
        return f1 + f2

    def parse_tree_class(self, root, base_class="Resource", api_doc_annotation="doc"):
        functions = []
        for child in ast.iter_child_nodes(root):
            if isinstance(child, ast.ClassDef):
                bases = [base.id for base in child.bases]
                if base_class not in bases:
                    logging.warning("Ignoring class %s", child.name)
                    continue
                for fn in ast.iter_child_nodes(child):
                    if not isinstance(fn, ast.FunctionDef):
                        continue
                    if fn.name not in self.http_verbs:
                        logging.warning("Skipping function with name %s", fn.name)
                        continue
                    parsed_fn = parse_child_function(
                        fn,
                        api_method_annotation=None,
                        is_api_method=True,
                        api_doc_annotation=api_doc_annotation
                    )
                    try:
                        assert parsed_fn is not None
                    except AssertionError as e:
                        logging.error("Function '%s' could not be parsed", fn.name)
                        raise e
                    functions.append(parsed_fn)
        return functions

    def parse_tree_functions(self, root, api_method_annotation):
        functions = []
        for child in ast.iter_child_nodes(root):
            if not isinstance(child, ast.FunctionDef):
                continue
            if child.name == "show_api":
                logging.debug("Skipping custom-named function show_api")
                continue
            try:
                fn = parse_child_function(child, api_method_annotation)
            except Exception as e:
                logging.error("Failed to parse function '%s' in file %s", child.name, self.fname)
                logging.error("Function details: %s", child.__dict__)
                raise e
            if fn is None:
                continue
            assert fn.routes != [], "route must be set"
            functions.append(fn)
        return functions


def is_parametrized_component(item):
    #TODO this is a giant hack
    return item in ["<int:entry_id>", "<int:doc_id>"]


def generate_docs_for_function(fn, expected_route_prefix):
    """
    Generate HTML documentation for the given function
    """
    html = ""
    #TODO use some sort of HTML generation plugin to do this
    html += ("""<div class="method-section">""")
    assert fn.routes[-1].startswith(expected_route_prefix), fn.routes[-1]
    l = fn.routes[-1].replace(expected_route_prefix, "").split("/")
    if is_parametrized_component(l[-1]):
        l[-1] = "id"
    mangled_route = "_".join(l)
    internal_anchor = "{method}_{mangled_route}".format(
        method=fn.http_methods[0].lower(),
        mangled_route=mangled_route
    )
    http_method = fn.http_methods[0].lower()
    uri = fn.routes[-1]
    table = str.maketrans({ "<": "&lt;", ">": "&gt;" })
    uri = uri.translate(table)
    html += ("""<h2 id="{internal_anchor}">
        <span class="http-method">{http_method}</span>
        <span class="uri">{uri}</span>
    </h2>""".format(
        internal_anchor=internal_anchor,
        http_method=http_method.upper(),
        uri=uri
    ))

    html += ("""<p class="about">{about}</p>""".format(
        about=fn.about.rstrip()))

    html += ("<h3>Arguments</h3>")
    if fn.arguments == [] and not fn.requires_csrf_token:
        html += ("<p>None</p>")
    else:
        # newlines are important here
        html += ('<pre><code data-lang="javascript">')
        html += '{\n'
        if fn.requires_csrf_token:
            html += '\t"csrf_token": string (required)'
        if fn.requires_csrf_token and fn.arguments != []:
            html += ',\n'
        for arg in fn.arguments:
            required_s = ("(required)" if arg["is_required"] else "(optional)")
            html += '\t"{name}": {val}'.format(
                name=arg["name"],
                val="%s (%s),\n" % (arg["type"], required_s)
            )
        # take out trailing ',\n'
        html = html[:-2]
        html += '\n}\n'
        html += ("</code></pre>")

    html += ("<h3>Response</h3>")
    html += "<div>"
    for block in fn.response:
        if block["type"] == "text":
            html += "<p>{text}</p>".format(text=block["val"])
        else:
            code = block["val"].strip()
            html += '<pre><code data-lang="javascript">{code}</code></pre>'.format(code=code)
    html += "</div>"

    html += ("<h3>Status codes</h3>")
    html += ("<ul>")
    for status_code in sorted(fn.status_codes):
        html += """<li>
                    <span class='http-status-code'>{code}</span> - {s}
                </li>""".format(
            code=status_code,
            s=fn.status_codes[status_code]
        )
    html += ("</ul>")

    html += ('</div>')

    soup = BeautifulSoup(html, "html.parser")
    return soup
    # print(soup.prettify())


def get_internal_anchor_for_function(fn, expected_route_prefix):
    assert expected_route_prefix.endswith("/")
    assert fn.routes[-1].startswith(expected_route_prefix), fn.routes[-1]
    l = fn.routes[-1].replace(expected_route_prefix, "").split("/")
    if is_parametrized_component(l[-1]):
        l[-1] = "id"
    mangled_route = "_".join(l)
    internal_anchor = "{method}_{mangled_route}".format(
        method=fn.http_methods[0].lower(),
        mangled_route=mangled_route
    )
    return "#" + internal_anchor


def filename_from_function(fn, expected_route_prefix):
    assert expected_route_prefix.endswith("/")
    assert fn.routes[-1].startswith(expected_route_prefix), fn.routes[-1]
    l = fn.routes[-1].replace(expected_route_prefix, "").split("/")
    if is_parametrized_component(l[-1]):
        l[-1] = "id"
    mangled_route = "_".join(l)
    internal_anchor = "{method}_{mangled_route}".format(
        method=fn.http_methods[0].lower(),
        mangled_route=mangled_route
    )
    return internal_anchor + ".html"


def generate_method_table(functions, expected_route_prefix):
    rows = []
    glyphs = {
        True: '<span class="glyphicon glyphicon-ok"><span class="sr-only">Yes</span></span>',
        False: '<span class="glyphicon glyphicon-remove"><span class="sr-only">No</span></span>'
    }
    for function in sorted(functions, key=lambda fn: fn.routes[-1]):
        trans_table = str.maketrans({ "<": "&lt;", ">": "&gt;" })
        route = function.routes[-1].translate(trans_table)
        row = """<tr>
            <td><a href="{internal_anchor}">{method} {route}</a></td>
            <td class="about">{about}</td>
            <td class="requires-login">{requires_login_glyph}</td>
            <td class="requires-csrf-token">{requires_csrf_token_glyph}</td>
        </tr>""".format(
            internal_anchor=get_internal_anchor_for_function(function, expected_route_prefix),
            method=function.http_methods[0],
            route=route,
            about=function.about,
            requires_login_glyph=glyphs[function.requires_auth],
            requires_csrf_token_glyph=glyphs[function.requires_csrf_token]
        )
        rows.append(row)
    template = """
    <table id="method-table" class="table table-striped">
        <thead>
            <tr>
                <th>Method &amp; path</th>
                <th>Description</th>
                <th>Requires login</th>
                <th>Requires CSRF token</th>
            </tr>
        </thead>
        <tbody>
            {body}
        </tbody>
    </table>
    """.format(body="\n".join(rows))
    return BeautifulSoup(template, "html.parser")


def write_method_table(method_table_soup, output_folder):
    fname = os.path.join(output_folder, "method_table.html")
    with open(fname, "w") as fp:
        fp.write(method_table_soup.prettify())
    logging.info("Wrote method table to %s" % fname)


def write_function_docs_html(fn, expected_route_prefix, output_folder):
    function_soup = generate_docs_for_function(fn, expected_route_prefix)
    fname = os.path.join(output_folder, filename_from_function(fn, expected_route_prefix))
    with open(fname, "w") as fp:
        fp.write(function_soup.prettify())
        logging.info("Wrote file " + fname)


def write_function_docs_json(functions, expected_route_prefix, output_fname):
    """Generate a swagger-like representation of the API
    """
    # maintain a pointer to this object for easy access
    # schemas = {}
    swagger = {
        "swagger": "2.0",
        "consumes": ["application/json"],
        "produces": ["application/json"],
        "paths": {},
        # "components": { "schemas": schemas }
    }
    for fn in functions:
        for route in fn.routes:
            if route not in swagger["paths"]:
                swagger["paths"][route] = {}
            for method in fn.http_methods:
                method = method.lower()
                if method in swagger["paths"][route]:
                    logging.error("Duplicate route and method for route %s and method %s", route, method)
                    logging.error(swagger["paths"][route])
                    raise AssertionError("Duplicate route and method")
                # parse the arguments here
                swagger_fn = {
                    "description": fn.about.strip(),
                    "parameters": fn.arguments,
                    "responses": {}
                }
                if fn.requires_csrf_token:
                    swagger_fn["parameters"].append({
                        "name": "csrf_token",
                        "type": "string",
                        "required": True
                    })
                on_success_index = None
                on_error_index = None
                for i, block in enumerate(fn.response):
                    if block["val"].startswith("on success:"):
                        on_success_index = i
                    elif block["val"].startswith("on error:"):
                        on_error_index = i
                for code, description in fn.status_codes.items():
                    response_obj = {
                        "description": description.strip(),
                    }
                    if code == 200:
                        if on_success_index is None:
                            content_arr = fn.response
                        else:
                            if fn.response[on_success_index]["val"] == "on success:\n":
                                on_success_index += 1
                            content_arr = fn.response[on_success_index: on_error_index]
                    else:
                        if on_error_index is None:
                            # don't add anything
                            content_arr = []
                        else:
                            if len(fn.response) == 1:
                                content_arr = fn.response
                            else:
                                assert on_error_index > on_success_index
                                if fn.response[on_error_index]["val"] == "on error:\n":
                                    on_error_index += 1
                                content_arr = fn.response[on_error_index:]

                    if content_arr == []:
                        pass
                    elif len(content_arr) == 1:
                        if content_arr[0]["type"] == "code":
                            # for prettier formatting
                            response_obj["content"] = content_arr[0]["val"].strip().replace("\"", "'")
                            # try:
                                # response_obj["content"] = json.loads(arr[0]["val"].strip())
                            # except Exception as e:
                                # print(arr[0]["val"].strip())
                                # raise e
                        else:
                            response_obj["content"] = content_arr[0]["val"].strip()
                    else:
                        response_obj["content"] = content_arr
                    swagger_fn["responses"][code] = response_obj

                # convert the function to swagger
                swagger["paths"][route][method] = swagger_fn
    with open(output_fname, "w") as fp:
        json.dump(swagger, fp, indent=4, sort_keys=True)
    logging.debug("Wrote to file %s", output_fname)


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("fname",
        help="Filename where the code lives")
    parser.add_argument("api_method_annotation",
        help="For example if methods annotation is @api_v1.routes, specify 'api_v1'")
    parser.add_argument("route_prefix",
        help="For example: /api/v1/")
    parser.add_argument("dest",
        help="What folder to write everything to")
    parser.add_argument("--output-format", choices=["html", "json"], default="html",
        help="If JSON specified, print out intermediate representation" + "\n" + \
                "If HTML specified, write out some pretty webpage")
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG, format="[%(levelname)s] %(message)s")
    coloredlogs.install(level=logging.DEBUG)

    assert args.route_prefix.endswith("/")
    with open(args.fname) as fp:
        contents = fp.read()
    root = ast.parse(contents)
    api_parser = ApiParser(args.fname)
    functions = api_parser.parse_tree(root, args.api_method_annotation)
    if args.output_format == "html":
        # method table
        soup = generate_method_table(functions, args.route_prefix)
        write_method_table(soup, args.dest)

        # one HTML page per function

        for fn in sorted(functions, key=lambda fn: fn.routes[-1]):
            try:
                write_function_docs_html(fn, args.route_prefix, args.dest)
            except Exception as e:
                logging.error("Failed to generate docs for function %s", fn.name)
                raise e
    else:
        write_function_docs_json(
            functions,
            args.route_prefix,
            args.dest + "/" + args.api_method_annotation + ".json"
        )

