import unittest
from autoaudit.html import HTMLReport, HTMLText, TextStyle

class TestHtmlFormatring(unittest.TestCase):
    def test_html_table(self):
        report = HTMLReport(
            HTMLText("one", TextStyle.BOLD),
            HTMLText("two", TextStyle.ITALIC),
            HTMLText("three")
        )

        expected = "<table>\n<tr>\n\t<th><b>one</b>"\
                   "</th>\n\t<th><i>two</i></th>\n\t"\
                   "<th>three</th>\n</tr>\n</table>"
        self.assertEqual(str(report), expected) 
