import random
import subprocess
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from core.mitre import LOGIN_PATHS
from core.parser import parse_line
from tools.data_for_generators import SQLI_PAYLOADS, XSS_PAYLOADS
from tools.generate_logs import ALL_ATTACKS, INTENSITY_PRESETS, _parse_attacks, attack_campaign


class LogGenerationTests(unittest.TestCase):
    def test_default_attack_list_contains_only_supported_modes(self):
        self.assertEqual(ALL_ATTACKS, ["bruteforce", "sqli", "xss", "dos"])
        self.assertEqual(_parse_attacks(None), ALL_ATTACKS)

    def test_campaign_uses_only_supported_attack_stages(self):
        random.seed(7)
        lines: list[str] = []
        start = datetime(2026, 1, 10, 9, 0, 0, tzinfo=timezone(timedelta(hours=3)))

        attack_campaign(lines, "combined", start, "45.133.12.77", INTENSITY_PRESETS["low"])

        parsed_rows = [parse_line(line) for line in lines]
        for row in parsed_rows:
            self.assertIsNotNone(row)
            target = f"{row['path']}?{row['query']}" if row["query"] else row["path"]
            self.assertTrue(
                row["path"].startswith(LOGIN_PATHS) or target in SQLI_PAYLOADS or target in XSS_PAYLOADS,
                msg=target,
            )

    def test_cli_help_does_not_expose_removed_modes_or_flags(self):
        script = Path(__file__).resolve().parents[1] / "tools" / "generate_logs.py"
        result = subprocess.run(
            [sys.executable, str(script), "--help"],
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0)
        self.assertNotIn("scanning", result.stdout)
        self.assertNotIn("lfi", result.stdout)
        self.assertNotIn("--scan-seconds", result.stdout)
        self.assertNotIn("--lfi-count", result.stdout)

    def test_cli_rejects_removed_mode(self):
        script = Path(__file__).resolve().parents[1] / "tools" / "generate_logs.py"
        result = subprocess.run(
            [sys.executable, str(script), "--mode", "scanning"],
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("invalid choice", result.stderr)


if __name__ == "__main__":
    unittest.main()
