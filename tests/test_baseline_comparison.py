import unittest

import pandas as pd

from core.accuracy import compare_with_regex_baseline


class BaselineComparisonTests(unittest.TestCase):
    def test_reports_regex_overlap_without_accuracy_fields(self):
        ts = pd.Timestamp("2026-01-10T10:00:00+03:00")
        ml_incidents = [{"type": "SQLI", "ip": "1.1.1.1", "start": ts, "evidence": "ml"}]
        regex_incidents = [{"type": "SQLI", "ip": "1.1.1.1", "start": ts, "evidence": "regex"}]

        metrics = compare_with_regex_baseline(None, ml_incidents, regex_incidents)

        self.assertEqual(metrics["comparison_kind"], "regex_baseline_overlap")
        self.assertEqual(metrics["agreement_rate"], 1.0)
        self.assertEqual(metrics["overlap"], 1)
        self.assertNotIn("precision", metrics)
        self.assertNotIn("recall", metrics)
        self.assertNotIn("f1", metrics)


if __name__ == "__main__":
    unittest.main()
