"""
This is legacy stuff. I moved it out of create_api_docs but I might need it eventually
"""


import logging
import re

from enum import Enum, unique


def parse_docstring(docstring):
    """
    This was a parser for a previous format of docstring I had
    As the grammar got more difficult, I realized I could just use RST
    The grammar could be defined as:

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

    ResponseBlock :=
    (Line | CodeBlock)+ | (SuccessBlock
    ErrorBlock?)

    SuccessBlock :=
    'on success:
        (Line | CodeBlock)+

    ErrorBlack := 
    'on error:
        (Line | CodeBlock)+

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

    @unique
    class State(Enum):
        INSIDE_ABOUT = 1
        EXPECT_SECTION_HEADER = 2
        INSIDE_ARGUMENTS = 3
        INSIDE_RESPONSE = 4
        INSIDE_STATUS_CODES = 5
        INSIDE_RESPONSE_CODE = 6

    valid_section_headers = ["Arguments", "Response", "Status codes"]

    # the first section is unlabelled
    state = State.INSIDE_ABOUT 

    # TODO I have no idea if there is a program that converts grammars to state machines or not
    # but there should be because this is a fucking mess

    for i, line in enumerate(docstring.split("\n")):
        # first, convert leading spaces to tabs
        while line.startswith(" " * 4):
            line = line.replace(" " * 4, "\t", 1)
        # then get the indentation level because that's important
        indentation_level = 0
        for c in line:
            if c == "\t":
                indentation_level += 1
            else:
                break
        if indentation_level == 0 and state not in [State.INSIDE_ABOUT, State.EXPECT_SECTION_HEADER] \
                and line != "":
            state = State.EXPECT_SECTION_HEADER

        if state == State.INSIDE_ABOUT:
            if line.strip() == "":
                state = State.EXPECT_SECTION_HEADER
            else:
                self.about += line + "\n"
        elif state == State.EXPECT_SECTION_HEADER:
            try:
                assert line.rstrip().endswith(":")
            except AssertionError as e:
                logging.error("error parsing docstring for function '%s'", self.name)
                logging.error("expected section header '%s' to end with ':' (line %d)", line, i)
                raise SystemExit(1)
            section_name = line.strip().rstrip(":")
            assert section_name in valid_section_headers, "Invalid section '%s'" % section_name
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
            pattern = re.compile(r'(\w+): (\w+) (\(\w+\))?$')
            m = pattern.match(arg)
            try:
                arg_name = m.group(1)
                arg_type = m.group(2)
                required = m.group(3) == "(required)"
                self.add_argument(arg_name, arg_type, required)
            except Exception as e:
                print(pattern)
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
                # state = State.EXPECT_SECTION_HEADER
                # actually spaces are totally fine
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

