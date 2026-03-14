import unittest

import pandas as pd

from core.accuracy import merge_incident_sources


class IncidentMergeTests(unittest.TestCase):
    def test_merges_ml_and_regex_into_single_incident(self):
        ts = pd.Timestamp("2026-01-10T10:02:00+03:00")
        ml_incidents = [
            {
                "type": "SQLI",
                "severity": "MEDIUM",
                "ip": "1.1.1.1",
                "start": ts,
                "end": ts + pd.Timedelta(minutes=1),
                "confidence": 0.91,
                "request_count": 5,
                "evidence": "ml evidence",
            }
        ]
        regex_incidents = [
            {
                "type": "SQLI",
                "severity": "HIGH",
                "ip": "1.1.1.1",
                "start": ts,
                "end": ts,
                "evidence": "regex evidence",
            }
        ]

        merged = merge_incident_sources(ml_incidents, regex_incidents)

        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["source"], "ML + Regex")
        self.assertEqual(merged[0]["request_count"], 5)
        self.assertEqual(merged[0]["severity"], "HIGH")
        self.assertAlmostEqual(merged[0]["confidence"], 0.91)

    def test_collapses_duplicate_regex_hits_in_same_window(self):
        ts = pd.Timestamp("2026-01-10T10:00:30+03:00")
        regex_incidents = [
            {
                "type": "XSS",
                "severity": "HIGH",
                "ip": "2.2.2.2",
                "start": ts,
                "end": ts,
                "evidence": "first hit",
            },
            {
                "type": "XSS",
                "severity": "HIGH",
                "ip": "2.2.2.2",
                "start": ts + pd.Timedelta(seconds=20),
                "end": ts + pd.Timedelta(seconds=20),
                "evidence": "second hit",
            },
        ]

        merged = merge_incident_sources([], regex_incidents)

        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["source"], "Regex")
        self.assertEqual(merged[0]["request_count"], 2)
        self.assertIn("related events", merged[0]["evidence"])


if __name__ == "__main__":
    unittest.main()
