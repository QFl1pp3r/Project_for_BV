import random
import unittest
from datetime import datetime, timedelta, timezone

import pandas as pd

from parser import parse_line
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

        counts = dataset["label"].value_counts()
        self.assertGreater(counts["NORMAL"], counts["DOS"])
        self.assertGreater(counts["NORMAL"], counts["SQLI"])

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


if __name__ == "__main__":
    unittest.main()
