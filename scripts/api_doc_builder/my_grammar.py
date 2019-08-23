from parsimonious.grammar import Grammar

# grammar = Grammar(
        # """
        # code_block = code_start code_text code_end
        # whitespace = (" " / "\\t" / "\\n")+
        # code_content = !"```" .
        # code_text = whitespace? code_content whitespace?
        # code_start = "```"
        # code_end = "```"
        # """
# )
# grammar = Grammar(
        # """
        # newline = "\\n"
        # response_block = response_title newline response_content
        # response_content = (code_block / line)+
        # line = text newline
        # text = (!newline ~".")+
        # response_title = "Response:"
        # code_block = code_start code_text code_end
        # code_start = "```"
        # code_end = "```"
        # code_text = (!code_end (~"." / "\\n"))+
        # """
# )
grammar = Grammar(
        """
        doc = whitespace? about_section section+

        about_section = about_line+
        about_line = !"=" (~"."*) newline

        section = arguments_section / response_section

        arguments_section = arguments_title whitespace? arguments_body whitespace?
        arguments_title = "= Arguments" newline
        arguments_body = ("none" newline) / (arguments_list_item)+
        arguments_list_item = "- " arg_name ": " arg_type " (" required_or_optional ")" newline
        arg_name = ~"[a-zA-Z_0-9]"+
        arg_type = "number" / "string" / "boolean"
        required_or_optional = "required" / "optional"

        response_section = response_title whitespace? response_body whitespace?
        response_title = "= Response" newline
        response_body = (code_section / response_line / newline)+
        response_line = (!newline !code_delim ~".")+ newline
        code_section = code_delim newline code_section_body code_delim newline
        code_delim = "```"
        code_section_body = (!code_delim ~".")*

        whitespace = (" " / "\\t" / "\\n")*
        newline = "\\n"
        """

        # """
        # section = title whitespace? (list_item / paragraph / code_section)+
        # list_item = "- " list_body newline
        # list_body = ~"[0-9]"+ ": " (~"[A-Z ]*"i)+


        # title = "=" ~"[A-Z ]*"i newline
        # paragraph = (line)+
        # line = (~"[A-Z ]*"i )+ newline

        # code_section = "```" newline

        # """
)

code_block = """
This is the start of the about block
More about text

= Arguments

- arg1: string (required)
- arg2: boolean (optional)
- arg3_with_underscore: number (optional)

= Response

This is the response section

```
Here is some code in the response section
more code
```
"""
"""

= Status codes

- 100: bad
- 200: good
"""


"""
on success we would see this:

```
{ hello : world }
```

on failure we would see this:

```
{ goodbye: cruel, world: ! }
```

and that's about it
"""

# grammar = Grammar(
        # """
        # top_level_thing = (not_stop_char)+ "STOP"
        # not_stop_char = !"STOP" "a"
        # """
# )

# code_block = "aaaaSTOP"

# code_block = """```
# hello
# ```"""

result = grammar.parse(code_block)
print(result)
