import unittest

from core.parser import parse_line


class ParserTests(unittest.TestCase):
    def test_parses_request_target_with_embedded_quotes_and_spaces(self):
        line = (
            '45.133.12.77 - - [15/Mar/2026:00:41:11 +0300] '
            '"GET /products?id=1" OR "1"="1 HTTP/1.1" 400 1858 "-" '
            '"sqlmap/1.7.11#stable (https://sqlmap.org)"'
        )

        parsed = parse_line(line)

        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["method"], "GET")
        self.assertEqual(parsed["path"], "/products")
        self.assertEqual(parsed["query"], 'id=1" OR "1"="1')
        self.assertEqual(parsed["status"], 400)


if __name__ == "__main__":
    unittest.main()
