import docutils.parsers.rst
import docutils
import logging


def parse_rst(text):
    parser = docutils.parsers.rst.Parser()
    components = (docutils.parsers.rst.Parser,)
    settings = docutils.frontend.OptionParser(components=components).get_default_values()
    document = docutils.utils.new_document('<rst-doc>', settings=settings)
    parser.parse(text, document)
    return document


def get_bullet_list_children(node):
        l = [c for c in node.children if c.tagname == "bullet_list"]
        if l == []:
            logging.error("node does not have bullet_list child")
            logging.error("node is %s", str(node))
            raise AssertionError
        return l[0].children


def has_child_with_tag(node, tag):
    return tag in [c.tagname for c in node.children]


def get_text_child(node):
    i = node.first_child_matching_class(docutils.nodes.TextElement)
    return node.children[i]


def get_bullet_list_item_text(node):
    i = node.first_child_matching_class(docutils.nodes.TextElement)
    text_elem = node.children[i]
    return text_elem.astext()


def get_section_title(section):
    title = [c for c in section.children if c.tagname == "title"][0].astext()
    return title
