import unittest

try:
    import _helpers
except ImportError:  # pytest imports tests as a package
    from tests import _helpers

import parser as p  # noqa: E402
from bq_writer import (  # noqa: E402
    BigQueryWriter,
    PermanentWriteError,
    RecentIds,
    TransientWriteError,
    classify_exception,
    classify_row_errors,
)
from config import Settings  # noqa: E402

load_fixture = _helpers.load_fixture


class RecentIdsTests(unittest.TestCase):
    def test_lru_eviction(self):
        ids = RecentIds(capacity=2)
        ids.add("a")
        ids.add("b")
        self.assertIn("a", ids)  # touch a, so b is now oldest
        ids.add("c")
        self.assertIn("a", ids)
        self.assertNotIn("b", ids)
        self.assertIn("c", ids)
        self.assertEqual(len(ids), 2)


class ClassificationTests(unittest.TestCase):
    def test_exceptions(self):
        self.assertIsInstance(classify_exception(_helpers.HttpError(400)), PermanentWriteError)
        self.assertIsInstance(classify_exception(_helpers.HttpError(413)), PermanentWriteError)
        for code in (403, 404, 429, 500, 503):
            self.assertIsInstance(classify_exception(_helpers.HttpError(code)), TransientWriteError, code)
        self.assertIsInstance(classify_exception(TimeoutError()), TransientWriteError)

    def test_row_errors(self):
        self.assertIsInstance(
            classify_row_errors([{"index": 0, "errors": [{"reason": "invalid"}]}]), PermanentWriteError
        )
        self.assertIsInstance(
            classify_row_errors([{"index": 0, "errors": [{"reason": "timeout"}]}]), TransientWriteError
        )


class WriterTests(unittest.TestCase):
    def test_table_ids_without_project(self):
        fake = _helpers.FakeBigQueryClient()
        writer = BigQueryWriter(Settings(), client=fake)
        writer.write_parsed(p.parse_log_entry(load_fixture("sandbox_result.json")))
        self.assertEqual(fake.tables(), ["security_lab.security_events", "security_lab.sandbox_runs"])

    def test_custom_table_names(self):
        fake = _helpers.FakeBigQueryClient()
        settings = Settings.from_env(
            {
                "GCP_PROJECT_ID": "your-gcp-project-id",
                "SECURITY_DATASET": "sec",
                "SECURITY_EVENTS_TABLE": "events",
                "BQ_DATASET": "cm",
                "BQ_TABLE": "f",
                "PORT": "not-a-number",
            }
        )
        self.assertEqual(settings.port, 8080)
        writer = BigQueryWriter(settings, client=fake)
        writer.write_parsed(p.parse_log_entry(load_fixture("codemender_finding.json")))
        self.assertEqual(fake.tables(), ["your-gcp-project-id.sec.events", "your-gcp-project-id.cm.f"])

    def test_ingestion_error_row_truncated(self):
        fake = _helpers.FakeBigQueryClient()
        writer = BigQueryWriter(Settings(), client=fake)
        row = writer.write_ingestion_error("boom", b"x" * 300_000, message_id="m1", insert_id=None)
        self.assertLessEqual(len(row["raw_message"].encode()), 100_000)
        self.assertEqual(fake.calls[0]["row_ids"], ["m1"])
        self.assertEqual(fake.tables(), ["security_lab.ingestion_errors"])

    def test_lazy_client_uses_bigquery_module(self):
        stubbed = _helpers.install_bigquery_stub()
        writer = BigQueryWriter(Settings(project_id="your-gcp-project-id"))
        if not stubbed:
            self.skipTest("real google-cloud-bigquery installed; not creating a live client")
        client = writer.client
        self.assertEqual(client.project, "your-gcp-project-id")
        writer.write_parsed(p.parse_log_entry(load_fixture("iam_set_policy.json")))
        self.assertEqual(client.calls[0]["row_ids"], ["audit-setiam-0001"])


if __name__ == "__main__":
    unittest.main()
