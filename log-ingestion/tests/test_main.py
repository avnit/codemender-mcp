import base64
import json
import unittest

try:
    import _helpers
except ImportError:  # pytest imports tests as a package
    from tests import _helpers

from starlette.testclient import TestClient  # noqa: E402

import main  # noqa: E402
from bq_writer import BigQueryWriter  # noqa: E402
from config import Settings  # noqa: E402

load_fixture = _helpers.load_fixture
push_envelope = _helpers.push_envelope
FakeBigQueryClient = _helpers.FakeBigQueryClient
HttpError = _helpers.HttpError

SETTINGS = Settings(project_id="your-gcp-project-id")


def make_client(settings=SETTINGS, token_verifier=None):
    fake = FakeBigQueryClient()
    writer = BigQueryWriter(settings, client=fake)
    app = main.create_app(settings=settings, writer=writer, token_verifier=token_verifier)
    return TestClient(app), fake, writer


class HealthTests(unittest.TestCase):
    def test_health(self):
        client, _, _ = make_client()
        resp = client.get("/health")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), {"status": "ok", "service": "security-log-ingestion"})

    def test_push_is_post_only(self):
        client, _, _ = make_client()
        self.assertEqual(client.get("/pubsub/push").status_code, 405)


class PushSuccessTests(unittest.TestCase):
    def test_codemender_finding_writes_event_and_finding(self):
        client, fake, _ = make_client()
        resp = client.post("/pubsub/push", json=push_envelope(load_fixture("codemender_finding.json")))
        self.assertEqual(resp.status_code, 204)
        self.assertEqual(
            fake.tables(),
            [
                "your-gcp-project-id.security_lab.security_events",
                "your-gcp-project-id.codemender.findings",
            ],
        )
        event_call = fake.calls[0]
        self.assertEqual(event_call["row_ids"], ["cm-finding-0001"])
        self.assertEqual(event_call["rows"][0]["event_type"], "CODEMENDER_FINDING")
        self.assertEqual(fake.calls[1]["rows"][0]["finding_id"], "CM-0001")

    def test_sandbox_result_writes_event_and_run(self):
        client, fake, _ = make_client()
        resp = client.post("/pubsub/push", json=push_envelope(load_fixture("sandbox_result.json")))
        self.assertEqual(resp.status_code, 204)
        self.assertEqual(len(fake.calls_for("security_events")), 1)
        runs = fake.calls_for("sandbox_runs")
        self.assertEqual(len(runs), 1)
        self.assertEqual(runs[0]["rows"][0]["verdict"], "PATCH_VERIFIED")
        self.assertEqual(fake.calls_for("findings"), [])

    def test_iam_and_patch_write_event_only(self):
        client, fake, _ = make_client()
        for name in ("iam_set_policy.json", "codemender_patch.json"):
            resp = client.post("/pubsub/push", json=push_envelope(load_fixture(name), message_id=name))
            self.assertEqual(resp.status_code, 204, name)
        self.assertEqual(
            [c["rows"][0]["event_type"] for c in fake.calls],
            ["IAM_POLICY_CHANGE", "CODEMENDER_PATCH"],
        )

    def test_urlsafe_base64_without_padding(self):
        client, fake, _ = make_client()
        envelope = push_envelope(load_fixture("iam_set_policy.json"))
        raw = json.dumps(load_fixture("iam_set_policy.json")).encode()
        envelope["message"]["data"] = base64.urlsafe_b64encode(raw).decode().rstrip("=")
        resp = client.post("/pubsub/push", json=envelope)
        self.assertEqual(resp.status_code, 204)
        self.assertEqual(len(fake.calls_for("security_events")), 1)


class DuplicateTests(unittest.TestCase):
    def test_duplicate_insert_id_skipped(self):
        client, fake, writer = make_client()
        entry = load_fixture("codemender_finding.json")
        first = client.post("/pubsub/push", json=push_envelope(entry, message_id="m1"))
        second = client.post("/pubsub/push", json=push_envelope(entry, message_id="m2"))
        self.assertEqual(first.status_code, 204)
        self.assertEqual(second.status_code, 204)
        self.assertEqual(len(fake.calls_for("security_events")), 1)
        self.assertEqual(len(fake.calls_for("findings")), 1)
        self.assertTrue(writer.is_duplicate("cm-finding-0001"))


class MalformedTests(unittest.TestCase):
    def _assert_error_row(self, fake, expect_message_id=True):
        self.assertEqual(fake.tables(), ["your-gcp-project-id.security_lab.ingestion_errors"])
        row = fake.calls[0]["rows"][0]
        self.assertTrue(row["error"])
        self.assertTrue(row["received_at"])
        if expect_message_id:
            self.assertEqual(row["message_id"], "msg-1")
            self.assertEqual(fake.calls[0]["row_ids"], ["msg-1"])
        return row

    def test_malformed_log_entry(self):
        client, fake, _ = make_client()
        resp = client.post("/pubsub/push", json=push_envelope(load_fixture("malformed.json")))
        self.assertEqual(resp.status_code, 204)
        row = self._assert_error_row(fake)
        self.assertIn("CM-9999", row["raw_message"])

    def test_data_not_json(self):
        client, fake, _ = make_client()
        resp = client.post("/pubsub/push", json=push_envelope("{not json"))
        self.assertEqual(resp.status_code, 204)
        row = self._assert_error_row(fake)
        self.assertEqual(row["raw_message"], "{not json")
        self.assertIn("not JSON", row["error"])

    def test_data_not_object(self):
        client, fake, _ = make_client()
        resp = client.post("/pubsub/push", json=push_envelope("[1, 2]"))
        self.assertEqual(resp.status_code, 204)
        self._assert_error_row(fake)

    def test_data_not_base64(self):
        client, fake, _ = make_client()
        envelope = push_envelope({})
        envelope["message"]["data"] = "***not base64***"
        resp = client.post("/pubsub/push", json=envelope)
        self.assertEqual(resp.status_code, 204)
        self._assert_error_row(fake)

    def test_body_not_json(self):
        client, fake, _ = make_client()
        resp = client.post("/pubsub/push", content=b"hello", headers={"content-type": "text/plain"})
        self.assertEqual(resp.status_code, 204)
        row = self._assert_error_row(fake, expect_message_id=False)
        self.assertEqual(row["raw_message"], "hello")
        self.assertIsNone(fake.calls[0]["row_ids"])

    def test_missing_message(self):
        client, fake, _ = make_client()
        resp = client.post("/pubsub/push", json={"subscription": "x"})
        self.assertEqual(resp.status_code, 204)
        self._assert_error_row(fake, expect_message_id=False)

    def test_permanent_bigquery_rejection_goes_to_ingestion_errors(self):
        client, fake, _ = make_client()
        fake.fail["security_events"] = [{"index": 0, "errors": [{"reason": "invalid", "message": "bad"}]}]
        resp = client.post("/pubsub/push", json=push_envelope(load_fixture("iam_set_policy.json")))
        self.assertEqual(resp.status_code, 204)
        error_calls = fake.calls_for("ingestion_errors")
        self.assertEqual(len(error_calls), 1)
        self.assertEqual(error_calls[0]["rows"][0]["insert_id"], "audit-setiam-0001")

    def test_bad_request_exception_is_permanent(self):
        client, fake, _ = make_client()
        fake.fail["security_events"] = HttpError(400, "bad request")
        resp = client.post("/pubsub/push", json=push_envelope(load_fixture("iam_set_policy.json")))
        self.assertEqual(resp.status_code, 204)
        self.assertEqual(len(fake.calls_for("ingestion_errors")), 1)


class TransientTests(unittest.TestCase):
    def test_server_error_returns_500(self):
        client, fake, writer = make_client()
        fake.fail["security_events"] = HttpError(503, "unavailable")
        resp = client.post("/pubsub/push", json=push_envelope(load_fixture("codemender_finding.json")))
        self.assertEqual(resp.status_code, 500)
        self.assertEqual(fake.calls_for("ingestion_errors"), [])
        self.assertFalse(writer.is_duplicate("cm-finding-0001"))

    def test_retry_after_transient_failure_succeeds(self):
        client, fake, _ = make_client()
        fake.fail["findings"] = ConnectionError("reset")
        envelope = push_envelope(load_fixture("codemender_finding.json"))
        self.assertEqual(client.post("/pubsub/push", json=envelope).status_code, 500)
        del fake.fail["findings"]
        self.assertEqual(client.post("/pubsub/push", json=envelope).status_code, 204)
        # security_events was sent twice with the same row ID; BigQuery dedupes best-effort.
        event_calls = fake.calls_for("security_events")
        self.assertEqual(len(event_calls), 2)
        self.assertEqual(event_calls[0]["row_ids"], event_calls[1]["row_ids"])

    def test_transient_row_error_returns_500(self):
        client, fake, _ = make_client()
        fake.fail["security_events"] = [{"index": 0, "errors": [{"reason": "backendError"}]}]
        resp = client.post("/pubsub/push", json=push_envelope(load_fixture("iam_set_policy.json")))
        self.assertEqual(resp.status_code, 500)

    def test_ingestion_errors_write_failure_returns_500(self):
        client, fake, _ = make_client()
        fake.fail["ingestion_errors"] = HttpError(500, "internal")
        resp = client.post("/pubsub/push", json=push_envelope("{not json"))
        self.assertEqual(resp.status_code, 500)


class AuthTests(unittest.TestCase):
    AUDIENCE = "https://security-log-ingestion.example.run.app/pubsub/push"

    def setUp(self):
        self.calls = []

        def verifier(token, audience):
            self.calls.append((token, audience))
            if token != "good-token":
                raise ValueError("bad signature")
            return {"email": "pubsub-push-sa@your-gcp-project-id.iam.gserviceaccount.com", "email_verified": True}

        self.verifier = verifier

    def _client(self, **overrides):
        settings = Settings(project_id="your-gcp-project-id", push_audience=self.AUDIENCE, **overrides)
        return make_client(settings=settings, token_verifier=self.verifier)

    def test_missing_token_401(self):
        client, fake, _ = self._client()
        resp = client.post("/pubsub/push", json=push_envelope(load_fixture("iam_set_policy.json")))
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(fake.calls, [])

    def test_invalid_token_401(self):
        client, fake, _ = self._client()
        resp = client.post(
            "/pubsub/push",
            json=push_envelope(load_fixture("iam_set_policy.json")),
            headers={"Authorization": "Bearer forged"},
        )
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(fake.calls, [])

    def test_valid_token_204(self):
        client, fake, _ = self._client()
        resp = client.post(
            "/pubsub/push",
            json=push_envelope(load_fixture("iam_set_policy.json")),
            headers={"Authorization": "Bearer good-token"},
        )
        self.assertEqual(resp.status_code, 204)
        self.assertEqual(self.calls, [("good-token", self.AUDIENCE)])
        self.assertEqual(len(fake.calls), 1)

    def test_service_account_mismatch_403(self):
        client, fake, _ = self._client(push_service_account="someone-else@example.iam.gserviceaccount.com")
        resp = client.post(
            "/pubsub/push",
            json=push_envelope(load_fixture("iam_set_policy.json")),
            headers={"Authorization": "Bearer good-token"},
        )
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(fake.calls, [])

    def test_no_audience_skips_check(self):
        client, fake, _ = make_client(token_verifier=self.verifier)
        resp = client.post("/pubsub/push", json=push_envelope(load_fixture("iam_set_policy.json")))
        self.assertEqual(resp.status_code, 204)
        self.assertEqual(self.calls, [])

    def test_health_needs_no_token(self):
        client, _, _ = self._client()
        self.assertEqual(client.get("/health").status_code, 200)


if __name__ == "__main__":
    unittest.main()
