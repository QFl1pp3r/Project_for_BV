import io
import os
import sys
import tempfile
import unittest

PROJECT_DIR = os.path.dirname(os.path.dirname(__file__))
MPL_CACHE_DIR = tempfile.mkdtemp(prefix="mplconfig_")
os.environ.setdefault("MPLCONFIGDIR", MPL_CACHE_DIR)
os.environ.setdefault("XDG_CACHE_HOME", MPL_CACHE_DIR)

if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

import app as app_module
from history_store import load_history, save_history


class AnalysisHistoryFlowTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.gen_dir = os.path.join(self.tmpdir.name, "generated")
        self.data_dir = os.path.join(self.tmpdir.name, "data")
        os.makedirs(self.gen_dir, exist_ok=True)
        os.makedirs(self.data_dir, exist_ok=True)

        self.old_gen_dir = app_module.GEN_DIR
        self.old_data_dir = app_module.DATA_DIR
        self.old_history_file = app_module.HISTORY_FILE

        app_module.GEN_DIR = self.gen_dir
        app_module.DATA_DIR = self.data_dir
        app_module.HISTORY_FILE = os.path.join(self.data_dir, "analysis_history.json")
        app_module.ensure_dir(app_module.GEN_DIR)
        app_module.ensure_dir(app_module.DATA_DIR)
        save_history(app_module.HISTORY_FILE, [])

        app_module.app.config.update(TESTING=True)
        self.client = app_module.app.test_client()

    def tearDown(self):
        app_module.GEN_DIR = self.old_gen_dir
        app_module.DATA_DIR = self.old_data_dir
        app_module.HISTORY_FILE = self.old_history_file
        self.tmpdir.cleanup()

    def _load_fixture(self, name: str) -> bytes:
        path = os.path.join(PROJECT_DIR, "test_logs", name)
        with open(path, "rb") as fh:
            return fh.read()

    def test_analysis_is_saved_to_history_and_can_be_deleted(self):
        response = self.client.post(
            "/analyze",
            data={"logfile": (io.BytesIO(self._load_fixture("demo_sqli.log")), "demo_sqli.log")},
            content_type="multipart/form-data",
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 302)
        self.assertIn("/report/", response.headers["Location"])

        analysis_id = response.headers["Location"].rstrip("/").rsplit("/", 1)[-1]
        history = load_history(app_module.HISTORY_FILE)
        self.assertEqual(len(history), 1)

        entry = history[0]
        self.assertEqual(entry["id"], analysis_id)
        self.assertEqual(entry["filename"], "demo_sqli.log")
        self.assertGreater(entry["summary"]["total_requests"], 0)

        for filename in entry["artifacts"].values():
            self.assertTrue(os.path.exists(os.path.join(app_module.GEN_DIR, filename)))

        report_response = self.client.get(response.headers["Location"])
        self.assertEqual(report_response.status_code, 200)
        self.assertIn("demo_sqli.log".encode("utf-8"), report_response.data)

        index_response = self.client.get("/")
        self.assertEqual(index_response.status_code, 200)
        self.assertIn("История анализов".encode("utf-8"), index_response.data)

        delete_response = self.client.post(f"/analysis/{analysis_id}/delete", follow_redirects=True)
        self.assertEqual(delete_response.status_code, 200)
        self.assertEqual(load_history(app_module.HISTORY_FILE), [])

        for filename in entry["artifacts"].values():
            self.assertFalse(os.path.exists(os.path.join(app_module.GEN_DIR, filename)))


if __name__ == "__main__":
    unittest.main()
