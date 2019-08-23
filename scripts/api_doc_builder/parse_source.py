#!/usr/bin/env python3

import ast
import logging
import re
from collections import OrderedDict

from enum import Enum, unique

IGNORED_FUNCTIONS = set(["show_api"])
IGNORED_DECORATORS = set([ "requires_json_form_validation" ])


class DocstringParseException(Exception):
    pass


@unique
class State(Enum):
    INSIDE_ABOUT = 1
    EXPECT_SECTION_HEADER = 2
    INSIDE_ARGUMENTS = 3
    INSIDE_RESPONSE = 4
    INSIDE_STATUS_CODES = 5
    INSIDE_RESPONSE_CODE = 6


class Function:
    def __init__(self, name):
        self.name = name

        # these are set in the docstring (added later)
        self.about = ""
        # map from argument names to values
        # preserve the order in which they are read
        self.arguments = OrderedDict()
        # map from status codes to their meanings
        self.status_codes = {}
        self.response = []

        self.routes = []
        self.http_methods = []
        self.requires_auth = False
        self.requires_csrf_token = False

    def set_docstring(self, docstring):
        assert docstring is not None, self.name + " has no docstring"
        self._parse_docstring(docstring)
        assert self.about != ""
        if self.status_codes == {}:
            raise DocstringParseException(
                "Expected to find status code list in docstring for function %s" % self.name)

    def _parse_docstring(self, docstring):
        """
        Here is the formal-ish grammar for the docstring. In retrospect it might have been easier to:
        (a) have used a formal-grammar parser
        (b) instead of creating my own formal grammar, used an existing formal grammar such

        Docstring := (\"\"\"About

        ArgumentsBlock

        ResponseBlock
        
        StatusCodeBlock
        \"\"\")

        ArgumentsBlock := 
        'Arguments:
        ArgumentList | 'none 

        ArgumentList := ArgumentListItem+

        ArgumentListItem :=
            '- ArgumentName: ArgumentType ('optional | 'required)

        ArgumentType := 'string | 'number | 'boolean

        ResponseBlock := (Line | CodeBlock)+

        CodeBlock :=
        '```
        Line+
        '```

        Line := a single line of any text without '```

        StatusCodeBlock :=
        'Status codes:
            '- StatusCode: Descr

        StatusCode := a number

        Descr := a line of text
        """
        valid_section_headers = ["Arguments", "Response", "Status codes"]
        # the first section is unlabelled
        state = State.INSIDE_ABOUT 
        for line in docstring.split("\n"):
            if state == State.INSIDE_ABOUT:
                if line.strip() == "":
                    state = State.EXPECT_SECTION_HEADER
                else:
                    self.about += line + "\n"
            elif state == State.EXPECT_SECTION_HEADER:
                assert line.rstrip().endswith(":"), "expected section header %s to end with :" % line
                section_name = line.strip().rstrip(":")
                assert section_name in valid_section_headers, "Invalid section " + section_name
                if section_name == "Arguments":
                    state = State.INSIDE_ARGUMENTS
                elif section_name == "Status codes":
                    state = State.INSIDE_STATUS_CODES
                elif section_name == "Response":
                    state = State.INSIDE_RESPONSE
            elif state == State.INSIDE_ARGUMENTS:
                if line.strip() == "":
                    state = State.EXPECT_SECTION_HEADER
                    continue
                if not line.lstrip().startswith("-"):
                    continue
                arg = line.lstrip().lstrip("- ")
                try:
                    head, tail = arg.split(": ", 1)
                    self.arguments[head] = tail
                except Exception as e:
                    print(self.name)
                    print(arg)
                    raise e
            elif state == State.INSIDE_STATUS_CODES:
                if line.strip() == "":
                    state = State.EXPECT_SECTION_HEADER
                    continue
                if not line.lstrip().startswith("-"):
                    continue
                arg = line.lstrip().lstrip("- ")
                head, tail = arg.split(": ", 1)
                status_code = int(head)
                self.status_codes[status_code] = tail
            elif state == State.INSIDE_RESPONSE:
                if line.strip() == "":
                    state = State.EXPECT_SECTION_HEADER
                    continue
                l = line.strip()
                if l == "```":
                    state = State.INSIDE_RESPONSE_CODE
                    self.response.append({ "type": "code", "val": "" })
                    continue
                m = re.match("```(.*?)```", l)
                if m:
                    self.response.append({ "type": "code", "val": m.group(1) })
                    continue
                # otherwise the line is just pure text
                if self.response == [] or self.response[-1]["type"] == "code":
                    self.response.append({ "type": "text", "val": "" })
                self.response[-1]["val"] += line.lstrip() + "\n"
            elif state == State.INSIDE_RESPONSE_CODE:
                l = line.strip()
                if l == "```":
                    state = State.INSIDE_RESPONSE
                    continue
                else:
                    assert self.response[-1]["type"] == "code"
                    self.response[-1]["val"] += line.lstrip() + "\n"

 
def parse_child_function(child, api_method_annotation):
    """Extract all the interesting information from the function.
    All we care about are the decorators, function name, and docstring"""
    fn = Function(child.name)
    is_api_method = False
    for decorator in child.decorator_list:
        if isinstance(decorator, ast.Name):
            if decorator.id == "requires_json_auth":
                fn.requires_auth = True
            elif decorator.id == "requires_csrf_check":
                fn.requires_csrf_token = True
            else:
                raise DocstringParseException("Found unrecognized decorator: %s" % decorator.id)
        elif isinstance(decorator, ast.Call):
            if isinstance(decorator.func, ast.Name):
                if decorator.func.id in IGNORED_DECORATORS:
                    # boring
                    pass
                else:
                    raise DocstringParseException("Found unrecognized decorator: %s" % decorator.func.id)
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
                else:
                    # this is just a helper method and doesn't need docs
                    logging.debug("function %s is not an API method and will be ignored" % fn.name)
                    return None
            else:
                raise DocstringParseException("Found invalid decorator: %s" % repr(decorator))
        else:
            raise DocstringParseException("Found invalid decorator: %s" % repr(decorator))
    if not is_api_method:
        logging.debug("function %s is not an API method and will be ignored" % fn.name)
        return None
    # only expect the functions that are API functions to have correct docs
    # otherwise we should ignore those functions
    fn.set_docstring(ast.get_docstring(child))
    return fn


def parse_tree(root, api_method_annotation):
    functions = []
    for child in ast.iter_child_nodes(root):
        if not isinstance(child, ast.FunctionDef):
            continue
        if child.name in IGNORED_FUNCTIONS:
            logging.debug("Skipping function in IGNORED_FUNCTIONS: %s" % child.name)
            continue
        try:
            fn = parse_child_function(child, api_method_annotation)
        except Exception as e:
            print("Failed to parse function %s" % child.__dict__)
            raise e
        if fn is None:
            continue
        assert fn.routes != [], "route must be set"
        functions.append(fn)
    return functions


if __name__ == "__main__":
    contents = """Retrieve all decrypted entries for the logged-in user

    Arguments:
        none

    Response:
        On success:
            ```
            [entry-1, entry-2, ... entry-n]
            ```
            The entry details depend on which version entries the user has.
            For details see passzero/models.py.
        On error:
            ```
            { "status": "error", "msg": string }
            ```

    Status codes:
        - 200: success
        - 401: user is not logged in
    """

    import asciidoc
    asciidoc(contents)
    
