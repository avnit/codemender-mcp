import json
import unittest

try:
    import _helpers
except ImportError:  # pytest imports tests as a package
    from tests import _helpers

import parser as p  # noqa: E402  (path set up by _helpers)

load_fixture = _helpers.load_fixture


class CoercionTests(unittest.TestCase):
    def test_coerce_int(self):
        self.assertEqual(p.coerce_int("42"), 42)
        self.assertEqual(p.coerce_int(" 7 "), 7)
        self.assertEqual(p.coerce_int(3.0), 3)
        self.assertEqual(p.coerce_int("3.0"), 3)
        self.assertIsNone(p.coerce_int(3.5))
        self.assertIsNone(p.coerce_int("abc"))
        self.assertIsNone(p.coerce_int(True))
        self.assertIsNone(p.coerce_int(None))
        self.assertIsNone(p.coerce_int({"a": 1}))

    def test_coerce_bool(self):
        for value in (True, "true", "TRUE", "yes", "1", 1):
            self.assertIs(p.coerce_bool(value), True, value)
        for value in (False, "false", "no", "0", 0):
            self.assertIs(p.coerce_bool(value), False, value)
        for value in (None, "maybe", 2, [], ""):
            self.assertIsNone(p.coerce_bool(value), value)

    def test_coerce_str(self):
        self.assertIsNone(p.coerce_str(""))
        self.assertEqual(p.coerce_str(5), "5")
        self.assertEqual(p.coerce_str({"b": 1, "a": 2}), '{"a": 2, "b": 1}')
        self.assertEqual(len(p.coerce_str("x" * 10_000)), p.MAX_STRING_CHARS)

    def test_coerce_enum(self):
        self.assertEqual(p.coerce_enum("not_exploitable", p.POC_STATES), "NOT_EXPLOITABLE")
        self.assertIsNone(p.coerce_enum("bogus", p.POC_STATES))


class TimestampTests(unittest.TestCase):
    def test_nanoseconds_truncated(self):
        self.assertEqual(
            p.parse_timestamp("2026-10-20T15:04:05.123456789Z"), "2026-10-20T15:04:05.123456Z"
        )

    def test_offset_converted_to_utc(self):
        self.assertEqual(
            p.parse_timestamp("2026-10-20T08:00:00-07:00"), "2026-10-20T15:00:00.000000Z"
        )
        self.assertEqual(
            p.parse_timestamp("2026-10-20 15:00:00+0000"), "2026-10-20T15:00:00.000000Z"
        )

    def test_epoch_seconds_and_millis(self):
        self.assertEqual(p.parse_timestamp(0), "1970-01-01T00:00:00.000000Z")
        self.assertEqual(p.parse_timestamp(1_700_000_000_000), p.parse_timestamp(1_700_000_000))
        self.assertEqual(p.parse_timestamp("1700000000"), p.parse_timestamp(1_700_000_000))

    def test_invalid(self):
        for value in (None, "", "not-a-timestamp", "2026-13-40T00:00:00Z", True, {}):
            self.assertIsNone(p.parse_timestamp(value), value)


class TruncationTests(unittest.TestCase):
    def test_short_text_unchanged(self):
        self.assertEqual(p.truncate_json_text('{"a": 1}', 100), '{"a": 1}')

    def test_long_text_wrapped_and_valid_json(self):
        text = json.dumps({"data": "é\"" * 50_000})
        out = p.truncate_json_text(text, 10_000)
        self.assertLessEqual(len(out.encode("utf-8")), 10_000)
        wrapped = json.loads(out)
        self.assertTrue(wrapped["truncated"])
        self.assertEqual(wrapped["original_bytes"], len(text.encode("utf-8")))
        self.assertTrue(text.startswith(wrapped["prefix"]))

    def test_raw_payload_capped(self):
        entry = load_fixture("codemender_finding.json")
        entry["jsonPayload"]["description"] = "A" * (p.MAX_RAW_PAYLOAD_BYTES * 2)
        row = p.build_security_event(entry)
        self.assertLessEqual(len(row["raw_payload"].encode("utf-8")), p.MAX_RAW_PAYLOAD_BYTES)
        self.assertTrue(json.loads(row["raw_payload"])["truncated"])


class ClassifyTests(unittest.TestCase):
    def test_fixtures(self):
        self.assertEqual(p.classify(load_fixture("codemender_finding.json")), "CODEMENDER_FINDING")
        self.assertEqual(p.classify(load_fixture("codemender_patch.json")), "CODEMENDER_PATCH")
        self.assertEqual(p.classify(load_fixture("sandbox_result.json")), "SANDBOX_RESULT")
        self.assertEqual(p.classify(load_fixture("iam_set_policy.json")), "IAM_POLICY_CHANGE")

    def test_codemender_short_event_type(self):
        entry = load_fixture("codemender_finding.json")
        entry["jsonPayload"]["event_type"] = "scan_started"
        self.assertEqual(p.classify(entry), "CODEMENDER_SCAN_STARTED")

    def test_codemender_event_type_requires_codemender_log(self):
        entry = load_fixture("codemender_finding.json")
        entry["logName"] = "projects/your-gcp-project-id/logs/something-else"
        self.assertEqual(p.classify(entry), "OTHER_SECURITY")

    def test_unknown_codemender_event(self):
        entry = load_fixture("codemender_finding.json")
        entry["jsonPayload"]["event_type"] = "HEARTBEAT"
        self.assertEqual(p.classify(entry), "OTHER_SECURITY")

    def test_sandbox_requires_job_name(self):
        entry = load_fixture("sandbox_result.json")
        entry["resource"]["labels"]["job_name"] = "other-job"
        self.assertEqual(p.classify(entry), "OTHER_SECURITY")

    def test_sandbox_result_in_text_payload(self):
        entry = load_fixture("sandbox_result.json")
        entry["textPayload"] = json.dumps(entry.pop("jsonPayload"))
        self.assertEqual(p.classify(entry), "SANDBOX_RESULT")
        self.assertEqual(p.build_sandbox_run(entry)["run_id"], "run-20261020-0001")

    def test_qualified_set_iam_policy(self):
        entry = load_fixture("iam_set_policy.json")
        entry["protoPayload"]["methodName"] = "google.iam.admin.v1.SetIAMPolicy"
        self.assertEqual(p.classify(entry), "IAM_POLICY_CHANGE")

    def test_other_audit_log(self):
        entry = load_fixture("iam_set_policy.json")
        entry["protoPayload"]["methodName"] = "v1.compute.instances.insert"
        self.assertEqual(p.classify(entry), "OTHER_SECURITY")
        self.assertEqual(p.build_security_event(entry)["source"], "cloud_audit")

    def test_non_dict(self):
        self.assertEqual(p.classify(["x"]), "OTHER_SECURITY")


class SecurityEventTests(unittest.TestCase):
    def test_codemender_finding_row(self):
        row = p.build_security_event(load_fixture("codemender_finding.json"), "2026-10-20T15:05:00Z")
        self.assertEqual(row["insert_id"], "cm-finding-0001")
        self.assertEqual(row["event_timestamp"], "2026-10-20T15:04:05.123456Z")
        self.assertEqual(row["ingest_timestamp"], "2026-10-20T15:05:00.000000Z")
        self.assertEqual(row["event_type"], "CODEMENDER_FINDING")
        self.assertEqual(row["source"], "codemender")
        self.assertEqual(row["severity"], "CRITICAL")  # finding severity wins for CodeMender
        self.assertEqual(row["project_id"], "your-gcp-project-id")
        self.assertEqual(row["resource_name"], "app/db.py")
        self.assertEqual(row["repository"], "your-github-org/payment-service")
        self.assertEqual(row["issue_id"], "CM-0001")
        self.assertEqual(row["summary"], "SQL injection in app/db.py")
        self.assertEqual(json.loads(row["raw_payload"])["insertId"], "cm-finding-0001")

    def test_row_has_exactly_schema_columns(self):
        with open(_helpers.ROOT_DIR + "/schema/security_events.json", encoding="utf-8") as f:
            columns = [c["name"] for c in json.load(f)]
        for name in ("codemender_finding.json", "sandbox_result.json", "iam_set_policy.json"):
            row = p.build_security_event(load_fixture(name))
            self.assertEqual(sorted(row), sorted(columns), name)

    def test_sandbox_event_row(self):
        row = p.build_security_event(load_fixture("sandbox_result.json"))
        self.assertEqual(row["source"], "sandbox")
        self.assertEqual(row["status"], "PATCH_VERIFIED")
        self.assertEqual(row["run_id"], "run-20261020-0001")
        self.assertEqual(row["resource_name"], "codemender-sandbox")
        self.assertEqual(row["severity"], "INFO")

    def test_iam_event_row(self):
        row = p.build_security_event(load_fixture("iam_set_policy.json"))
        self.assertEqual(row["event_type"], "IAM_POLICY_CHANGE")
        self.assertEqual(row["source"], "cloud_audit")
        self.assertEqual(row["principal"], "admin@example.com")
        self.assertEqual(row["resource_name"], "projects/your-gcp-project-id")
        self.assertIn("ADD roles/editor", row["summary"])
        self.assertEqual(row["severity"], "NOTICE")

    def test_timestamp_falls_back_to_receive_timestamp(self):
        entry = load_fixture("iam_set_policy.json")
        entry["timestamp"] = "garbage"
        self.assertEqual(p.build_security_event(entry)["event_timestamp"], "2026-10-20T16:00:01.000000Z")

    def test_missing_insert_id_raises(self):
        entry = load_fixture("iam_set_policy.json")
        del entry["insertId"]
        with self.assertRaises(p.ParseError):
            p.build_security_event(entry)

    def test_malformed_fixture_raises(self):
        with self.assertRaises(p.ParseError):
            p.parse_log_entry(load_fixture("malformed.json"))

    def test_non_dict_raises(self):
        with self.assertRaises(p.ParseError):
            p.parse_log_entry([1, 2])

    def test_project_from_log_name(self):
        entry = load_fixture("codemender_finding.json")
        entry["resource"] = {"type": "global"}
        self.assertEqual(p.build_security_event(entry)["project_id"], "your-gcp-project-id")


class SandboxRunTests(unittest.TestCase):
    def test_row_types_coerced(self):
        row = p.build_sandbox_run(load_fixture("sandbox_result.json"))
        self.assertEqual(row["run_id"], "run-20261020-0001")
        self.assertEqual(row["execution_name"], "codemender-sandbox-abc12")
        self.assertIs(row["patch_applied"], True)
        self.assertIs(row["unit_tests_passed"], True)
        self.assertEqual(row["tests_total"], 12)
        self.assertEqual(row["tests_failed"], 0)
        self.assertEqual(row["poc_before"], "EXPLOITABLE")
        self.assertEqual(row["poc_after"], "NOT_EXPLOITABLE")
        self.assertEqual(row["verdict"], "PATCH_VERIFIED")
        self.assertEqual(row["started_at"], "2026-10-20T15:19:00.000000Z")

    def test_columns_match_schema(self):
        with open(_helpers.ROOT_DIR + "/schema/sandbox_runs.json", encoding="utf-8") as f:
            columns = [c["name"] for c in json.load(f)]
        self.assertEqual(sorted(p.build_sandbox_run(load_fixture("sandbox_result.json"))), sorted(columns))

    def test_execution_name_from_labels(self):
        entry = load_fixture("sandbox_result.json")
        del entry["jsonPayload"]["execution_name"]
        self.assertEqual(p.build_sandbox_run(entry)["execution_name"], "codemender-sandbox-abc12")

    def test_missing_run_id_returns_none(self):
        entry = load_fixture("sandbox_result.json")
        del entry["jsonPayload"]["run_id"]
        self.assertIsNone(p.build_sandbox_run(entry))

    def test_not_sandbox(self):
        self.assertIsNone(p.build_sandbox_run(load_fixture("codemender_finding.json")))

    def test_bad_values_become_null(self):
        entry = load_fixture("sandbox_result.json")
        entry["jsonPayload"].update(
            {"tests_total": "many", "patch_applied": "perhaps", "verdict": "GREAT", "started_at": "soon"}
        )
        row = p.build_sandbox_run(entry)
        self.assertIsNone(row["tests_total"])
        self.assertIsNone(row["patch_applied"])
        self.assertIsNone(row["verdict"])
        self.assertIsNone(row["started_at"])


class FindingTests(unittest.TestCase):
    def test_row(self):
        row = p.build_finding(load_fixture("codemender_finding.json"))
        self.assertEqual(row["finding_id"], "CM-0001")
        self.assertEqual(row["line_number"], 42)
        self.assertEqual(row["severity"], "CRITICAL")
        self.assertEqual(row["status"], "DETECTED")
        self.assertEqual(row["cwe_id"], "CWE-89")
        self.assertEqual(row["wiz_issue_id"], "wiz-issue-0001")
        self.assertEqual(row["created_at"], "2026-10-20T15:04:05.123456Z")
        self.assertEqual(row["updated_at"], row["created_at"])

    def test_columns_match_schema(self):
        with open(_helpers.ROOT_DIR + "/schema/codemender_findings.json", encoding="utf-8") as f:
            columns = [c["name"] for c in json.load(f)]
        self.assertEqual(sorted(p.build_finding(load_fixture("codemender_finding.json"))), sorted(columns))

    def test_unknown_status_defaults_to_detected(self):
        entry = load_fixture("codemender_finding.json")
        entry["jsonPayload"]["status"] = "weird"
        self.assertEqual(p.build_finding(entry)["status"], "DETECTED")

    def test_patch_event_is_not_a_finding_row(self):
        self.assertIsNone(p.build_finding(load_fixture("codemender_patch.json")))

    def test_missing_finding_id_returns_none(self):
        entry = load_fixture("codemender_finding.json")
        del entry["jsonPayload"]["finding_id"]
        self.assertIsNone(p.build_finding(entry))


class ParseLogEntryTests(unittest.TestCase):
    def test_routes_rows(self):
        finding = p.parse_log_entry(load_fixture("codemender_finding.json"))
        self.assertIsNotNone(finding.finding)
        self.assertIsNone(finding.sandbox_run)

        sandbox = p.parse_log_entry(load_fixture("sandbox_result.json"))
        self.assertIsNotNone(sandbox.sandbox_run)
        self.assertIsNone(sandbox.finding)

        iam = p.parse_log_entry(load_fixture("iam_set_policy.json"))
        self.assertEqual(iam.insert_id, "audit-setiam-0001")
        self.assertIsNone(iam.sandbox_run)
        self.assertIsNone(iam.finding)


class SchemaFileTests(unittest.TestCase):
    def test_schema_files_are_valid(self):
        for name in ("security_events", "sandbox_runs", "ingestion_errors", "codemender_findings"):
            with open(f"{_helpers.ROOT_DIR}/schema/{name}.json", encoding="utf-8") as f:
                fields = json.load(f)
            for field in fields:
                self.assertEqual(set(field), {"name", "type", "mode", "description"}, name)
                self.assertIn(field["type"], {"STRING", "TIMESTAMP", "INT64", "BOOL"})
                self.assertIn(field["mode"], {"REQUIRED", "NULLABLE"})


if __name__ == "__main__":
    unittest.main()
