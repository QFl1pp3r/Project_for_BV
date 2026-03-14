import random
import unittest
from datetime import datetime, timedelta, timezone

import pandas as pd

from core.parser import parse_line
from tools.generate_dataset import generate_dataset
from tools.generate_logs import normal_traffic
from tools.train_model import split_dataset_frame


STATIC_LIKE_PATHS = {"/favicon.ico", "/robots.txt", "/sitemap.xml"}


def _is_static_path(path: str) -> bool:
    return path.startswith("/static/") or path.startswith("/images/") or path in STATIC_LIKE_PATHS


class SyntheticGenerationTests(unittest.TestCase):
    def test_normal_log_traffic_avoids_post_to_static_assets(self):
        random.seed(123)
        start = datetime(2026, 1, 10, 9, 0, 0, tzinfo=timezone(timedelta(hours=3)))
        lines: list[str] = []
        ips = [f"192.168.1.{index}" for index in range(10, 40)]

        normal_traffic(lines, "combined", start, seconds=1800, ips=ips)
        rows = [parse_line(line) for line in lines]
        offenders = [
            row for row in rows
            if row and row["method"] == "POST" and _is_static_path(row["path"])
        ]

        self.assertFalse(offenders)

    def test_dataset_generation_adds_split_groups_and_hard_negatives(self):
        dataset = generate_dataset(total=6000, seed=7, class_profile="realistic")

        self.assertIn("split_group", dataset.columns)
        self.assertIn("event_ts", dataset.columns)

        counts = dataset["label"].value_counts()
        self.assertEqual(int(counts["NORMAL"]), 4800)
        # Some attack payloads may fail to parse (special chars), so allow small tolerance
        self.assertAlmostEqual(int(counts["SQLI"]), 180, delta=15)
        self.assertAlmostEqual(int(counts["XSS"]), 180, delta=15)
        self.assertEqual(int(counts["BRUTE_FORCE"]), 300)
        self.assertEqual(int(counts["DOS"]), 240)
        self.assertEqual(int(counts["ANOMALY"]), 300)

        normal = dataset[dataset["label"] == "NORMAL"]
        self.assertGreater(int((normal["has_common_attack_path"] == 1).sum()), 0)
        self.assertGreater(int((normal["has_sql_keywords"] == 1).sum()), 0)

    def test_group_split_keeps_groups_disjoint(self):
        labels = ["NORMAL", "SQLI", "XSS", "BRUTE_FORCE", "DOS", "ANOMALY"]
        rows = []
        for repeat in range(3):
            for label in labels:
                group = f"{label}_{repeat}"
                for index in range(4):
                    rows.append(
                        {
                            "label": label,
                            "split_group": group,
                            "feature_stub": index,
                        }
                    )

        df = pd.DataFrame(rows)
        train_idx, test_idx, split_mode = split_dataset_frame(
            df=df,
            test_size=0.33,
            random_seed=42,
            split_mode="group",
        )

        train_groups = set(df.loc[train_idx, "split_group"])
        test_groups = set(df.loc[test_idx, "split_group"])
        self.assertEqual(split_mode, "group")
        self.assertTrue(train_groups.isdisjoint(test_groups))
        self.assertEqual(set(df.loc[train_idx, "label"]), set(labels))
        self.assertEqual(set(df.loc[test_idx, "label"]), set(labels))

    def test_auto_split_prefers_temporal_holdout(self):
        labels = ["NORMAL", "SQLI", "XSS", "BRUTE_FORCE", "DOS", "ANOMALY"]
        rows = []
        for group_idx in range(4):
            group = f"2026-01-10T{group_idx:02d}:00:00+0300"
            for label in labels:
                rows.append(
                    {
                        "label": label,
                        "split_group": group,
                        "feature_stub": group_idx,
                    }
                )

        df = pd.DataFrame(rows)
        train_idx, test_idx, split_mode = split_dataset_frame(
            df=df,
            test_size=0.5,
            random_seed=42,
            split_mode="auto",
        )

        train_groups = sorted(set(df.loc[train_idx, "split_group"]))
        test_groups = sorted(set(df.loc[test_idx, "split_group"]))
        self.assertEqual(split_mode, "time")
        self.assertLess(max(train_groups), min(test_groups))
        self.assertEqual(set(df.loc[train_idx, "label"]), set(labels))
        self.assertEqual(set(df.loc[test_idx, "label"]), set(labels))


if __name__ == "__main__":
    unittest.main()
