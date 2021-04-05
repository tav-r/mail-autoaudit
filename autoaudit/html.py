"""
Functions to generate HTML documents (for automated reports).

This is just a quick draft to see how this could be done.
"""

from enum import Enum
from typing import Tuple


class TextStyle(Enum):
    NONE=1
    ITALIC=2
    BOLD=3
    CODE=4

class HTMLText:
    def __init__(self, text: str = "", style: TextStyle = TextStyle.NONE):
        self.__style = style
        self.__text = text

    def __str__(self) -> str:
        return self._get_styled()

    def _get_styled(self) -> str:
        if self.__style is TextStyle.ITALIC:
            return f"<i>{self.__text}</i>"
        elif self.__style is TextStyle.BOLD:
            return f"<b>{self.__text}</b>"
        elif self.__style is TextStyle.CODE:
            return f"<code>{self.__text}</code>"
        return self.__text

    def __add__(self, other: "HTMLText"):
        return str(self) + str(other)


class HTMLReport:
    def __init__(self, *headings: HTMLText):
        self.__width = len(headings)

        table_headings = "".join([f"\n\t<th>{hdr}</th>" for hdr in headings])
        self.__raw = f"<tr>{table_headings}\n</tr>"

    def add_row(self, row: Tuple[HTMLText]):
        assert len(row) == self.__width

    def __str__(self) -> str:
        return f"<table>\n{self.__raw}\n</table>"

    @staticmethod
    def html_row(*row_elements: HTMLText) -> str:
        return "".join([f"\n\t<tr>{elt}</tr>" for elt in row_elements])
