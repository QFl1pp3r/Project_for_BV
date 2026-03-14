import unittest

import pandas as pd

from app import build_summary, ordered_attack_breakdown


class ReportingSummaryTests(unittest.TestCase):
    def test_summary_and_breakdown_separate_series_from_request_counts(self):
        df = pd.DataFrame(
            [
                {"ip": "1.1.1.1", "ts": pd.Timestamp("2026-03-15T02:00:00+03:00")},
                {"ip": "1.1.1.2", "ts": pd.Timestamp("2026-03-15T02:00:10+03:00")},
                {"ip": "1.1.1.2", "ts": pd.Timestamp("2026-03-15T02:00:20+03:00")},
            ]
        )
        incidents_df = pd.DataFrame(
            [
                {"type": "SQLI", "request_count": 30},
                {"type": "XSS", "request_count": 22},
                {"type": "SQLI", "request_count": 1},
            ]
        )

        summary = build_summary(df, incidents_df)
        breakdown = ordered_attack_breakdown(incidents_df)

        self.assertEqual(summary["incidents_total"], 3)
        self.assertEqual(summary["detected_requests_total"], 53)
        self.assertEqual(
            breakdown,
            [
                {"label": "SQLI", "incidents": 2, "requests": 31},
                {"label": "XSS", "incidents": 1, "requests": 22},
            ],
        )


if __name__ == "__main__":
    unittest.main()
