"""
Because flask-restplus has been successful at extracting route information, etc,
All I have to do is parse the description
"""

import logging
import re
from argparse import ArgumentParser
from pprint import pprint

import coloredlogs
import docutils
import yaml

from rst_utils import (get_bullet_list_children, get_bullet_list_item_text,
                       get_text_child, has_child_with_tag, parse_rst, get_section_title)


class ParsedDoc:
    def __init__(self):
        self.summary = None
        self.parameters = []
        self.response = []
        self.status_codes = {}

    def add_parameter(self, name: str, type: str, is_required: bool, subtypes=None):
        if subtypes:
            self.parameters.append({
                "name": name,
                "type": type,
                "is_required": is_required,
                "subtypes": subtypes
            })
        else:
            self.parameters.append({
                "name": name,
                "type": type,
                "is_required": is_required
            })

    def add_response(self, type: str, val: str, tag=None):
        if tag:
            self.response.append({
                "type": type,
                "val": val,
                "tag": tag
            })
        else:
            self.response.append({
                "type": type,
                "val": val
            })

    def add_status_code(self, status_code: int, description: str):
        assert status_code not in self.status_codes
        self.status_codes[status_code] = description


def parse_param(arg):
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
        print("Failed with this pattern:")
        print(pattern)
        print("Failed with this argument:")
        print(arg)
        print("Exception:")
        raise e


def parse_rst_docstring_response(node, parsed_doc, tag=None):
    l = [c for c in node.children if c.tagname != "title"]
    for child in l:
        if child.tagname == "paragraph":
            parsed_doc.add_response(type="text", val=child.astext(), tag=tag)
        elif child.tagname == "literal_block":
            parsed_doc.add_response(type="code", val=child.astext(), tag=tag)
        elif child.tagname == "section":
            parse_rst_docstring_response(child, parsed_doc,
                    tag=get_section_title(child))
        else:
            print(child)
            raise Exception


def parse_docstring_rst(docstring: str, http_method: str, route: str):
    """
    The response list will contain unparsed RST tags
    """
    doc = parse_rst(docstring)
    parsed_doc = ParsedDoc()
    logging.debug("Trying to parse [{method}] {route}".format(
        method=http_method, route=route))
    for i, section in enumerate(doc.children):
        if section.tagname == "section":
            # get the title
            title = get_section_title(section)
            if title == "Arguments":
                if has_child_with_tag(section, "bullet_list"):
                    for child in get_bullet_list_children(section):
                        # figure out if there is a nested type
                        if has_child_with_tag(child, "bullet_list"):
                            l = []
                            for subchild in get_bullet_list_children(child):
                                arg = parse_param(
                                    get_bullet_list_item_text(subchild)
                                )
                                d = { "name": arg["name"],
                                        "type": arg["type"],
                                        "is_required": arg["is_required"]
                                    }
                                l.append(d)
                            arg = parse_param(get_bullet_list_item_text(child))
                            parsed_doc.add_parameter(
                                name=arg["name"],
                                type=arg["type"],
                                is_required=arg["is_required"],
                                subtypes=l
                            )
                        else:
                            arg = parse_param(child.astext())
                            parsed_doc.add_parameter(
                                name=arg["name"],
                                type=arg["type"],
                                is_required=arg["is_required"]
                            )
                else:
                    logging.debug("ignoring arguments for [{method}] {route} because they are not in a bullet list".format(
                        method=http_method, route=route))
            elif title == "Status codes":
                for child in get_bullet_list_children(section):
                    arg = child.astext()
                    head, tail = arg.split(": ", 1)
                    parsed_doc.add_status_code(int(head), tail)
            elif title == "Response":
                parse_rst_docstring_response(section, parsed_doc)
            elif title == "Authentication":
                # get a text subnode
                child = get_text_child(section)
                parsed_doc.authentication = child.astext()
            else:
                logging.error("Error: unknown title: %s", title)
                raise Exception
        else:
            if isinstance(section, docutils.nodes.TextElement):
                parsed_doc.summary = section.astext()
    return parsed_doc


def docs_from_swagger_file(fname: str):
    with open(fname) as fp:
        swagger_conf = yaml.load(fp)
    for path in swagger_conf["paths"]:
        # the path is going to be a route
        for method, method_conf in swagger_conf["paths"][path].items():
            if method == "parameters":
                continue
            try:
                description = method_conf["description"]
            except Exception as e:
                print(method_conf)
                raise e
            # print("*" * 20)
            # print(description)
            # print("*" * 20)
            parsed_description = parse_docstring_rst(description, method, path)
            pprint(parsed_description.__dict__)


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("filename", help="swagger file to parse")
    args = parser.parse_args()
    logging.basicConfig(level=logging.DEBUG)
    coloredlogs.install(level=logging.DEBUG)
    docs_from_swagger_file(args.filename)
