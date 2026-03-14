import unittest

import pandas as pd

from core.detectors import detect_sqli
from core.mitre import SQLI_RE, XSS_RE
from core.ml_detector import _apply_signature_overrides, _build_signature_masks


class SignatureTests(unittest.TestCase):
    def test_sqli_regex_matches_boolean_payload_with_double_quotes(self):
        payload = '/products?id=1" OR "1"="1'
        self.assertRegex(payload, SQLI_RE)

    def test_sqli_regex_does_not_match_xss_payload_with_single_quotes(self):
        payload = "/search?q=<body onload=alert('xss')>"
        self.assertNotRegex(payload, SQLI_RE)
        self.assertRegex(payload, XSS_RE)

    def test_detect_sqli_excludes_xss_payloads(self):
        df = pd.DataFrame(
            [
                {
                    "ip": "1.1.1.1",
                    "ts": pd.Timestamp("2026-03-15T02:00:32+03:00"),
                    "method": "GET",
                    "path": "/search",
                    "query": "q=<body onload=alert('xss')>",
                    "status": 403,
                    "bytes": 372,
                }
            ]
        )

        self.assertEqual(detect_sqli(df), [])

    def test_detect_sqli_matches_urlencoded_payloads(self):
        df = pd.DataFrame(
            [
                {
                    "ip": "1.1.1.1",
                    "ts": pd.Timestamp("2026-03-15T02:02:15+03:00"),
                    "method": "GET",
                    "path": "/search",
                    "query": "q=%31%27%20%4f%52%20%31%3d%31--",
                    "status": 200,
                    "bytes": 1278,
                }
            ]
        )

        incidents = detect_sqli(df)
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["type"], "SQLI")

    def test_signature_override_prefers_xss_and_drops_unsupported_model_only_hits(self):
        requests = pd.DataFrame(
            [
                {
                    "path": "/search",
                    "query": "q=<body onload=alert('xss')>",
                    "ml_label": "SQLI",
                    "ml_confidence": 0.99,
                },
                {
                    "path": "/search",
                    "query": "q=laptop",
                    "ml_label": "XSS",
                    "ml_confidence": 0.98,
                },
            ]
        )

        sqli_mask, xss_mask = _build_signature_masks(requests)
        updated = _apply_signature_overrides(requests.copy(), sqli_mask=sqli_mask, xss_mask=xss_mask)

        self.assertEqual(updated.iloc[0]["ml_label"], "XSS")
        self.assertEqual(updated.iloc[1]["ml_label"], "NORMAL")


if __name__ == "__main__":
    unittest.main()
