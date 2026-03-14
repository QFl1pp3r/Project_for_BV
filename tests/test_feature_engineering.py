import unittest

import pandas as pd

from core.feature_engineering import FEATURE_COLUMNS, align_feature_columns, extract_features


class FeatureEngineeringTests(unittest.TestCase):
    def test_extracts_attack_indicators(self):
        df = pd.DataFrame(
            [
                {
                    "ip": "1.1.1.1",
                    "ts": pd.Timestamp("2026-01-10T10:00:00+03:00"),
                    "method": "GET",
                    "path": "/api/items",
                    "query": "q=1%20UNION%20SELECT%20password",
                    "status": 500,
                    "bytes": 321,
                }
            ]
        )

        features = extract_features(df)
        row = features.iloc[0]
        self.assertEqual(features.columns.tolist(), FEATURE_COLUMNS)
        self.assertEqual(int(row["has_sql_keywords"]), 1)
        self.assertGreaterEqual(int(row["sql_keyword_count"]), 2)
        self.assertEqual(int(row["has_encoded_chars"]), 1)
        self.assertEqual(int(row["status_group"]), 5)
        self.assertGreater(float(row["entropy"]), 0.0)

    def test_extracts_window_level_features(self):
        df = pd.DataFrame(
            [
                {
                    "ip": "10.0.0.5",
                    "ts": pd.Timestamp("2026-01-10T11:00:00+03:00"),
                    "method": "POST",
                    "path": "/login",
                    "query": "",
                    "status": 401,
                    "bytes": 200,
                },
                {
                    "ip": "10.0.0.5",
                    "ts": pd.Timestamp("2026-01-10T11:00:20+03:00"),
                    "method": "POST",
                    "path": "/login",
                    "query": "",
                    "status": 403,
                    "bytes": 180,
                },
                {
                    "ip": "10.0.0.5",
                    "ts": pd.Timestamp("2026-01-10T11:00:40+03:00"),
                    "method": "GET",
                    "path": "/account",
                    "query": "",
                    "status": 200,
                    "bytes": 900,
                },
            ]
        )

        features = extract_features(df)
        row = features.iloc[0]
        self.assertEqual(int(row["ip_req_count_5m"]), 3)
        self.assertEqual(int(row["ip_unique_paths_5m"]), 2)
        self.assertAlmostEqual(float(row["ip_error_rate_5m"]), 2 / 3, places=4)
        self.assertEqual(int(row["ip_login_fail_count_5m"]), 2)
        self.assertAlmostEqual(float(row["global_rps_1m"]), 3 / 60, places=6)

    def test_align_feature_columns_adds_missing_values(self):
        aligned = align_feature_columns(pd.DataFrame([{"url_length": 10, "entropy": 1.2}]))
        self.assertEqual(aligned.columns.tolist(), FEATURE_COLUMNS)
        self.assertEqual(int(aligned.iloc[0]["url_length"]), 10)
        self.assertEqual(float(aligned.iloc[0]["entropy"]), 1.2)
        self.assertEqual(int(aligned.iloc[0]["status_code"]), 0)


if __name__ == "__main__":
    unittest.main()
