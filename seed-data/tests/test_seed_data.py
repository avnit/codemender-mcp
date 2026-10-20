"""Seed data tests. No network, no google-cloud-bigquery.

Run from seed-data/:  PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
"""
import contextlib
import datetime as dt
import io
import json
import os
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import load_seed_data as L  # noqa: E402

REPO = "your-github-org/payment-service"
COMMIT = "3f2a9c1d8e7b6a5f4c3d2e1f0a9b8c7d6e5f4a3b"
RUN_RES = ("//run.googleapis.com/projects/your-gcp-project-id/locations/us-central1/"
           "services/payment-service")
UTC = dt.timezone.utc


def rows(name):
    return L.load_rows(name)


def read_json(rel):
    with open(os.path.join(ROOT, rel)) as fh:
        return json.load(fh)


class SchemaTests(unittest.TestCase):
    def test_every_table_has_schema_and_data(self):
        for name in L.TABLES:
            self.assertTrue(os.path.exists(os.path.join(ROOT, "schemas", name + ".json")), name)
            self.assertTrue(rows(name), f"{name}.jsonl is empty")

    def test_every_row_validates(self):
        for name in L.TABLES:
            self.assertEqual(L.validate_table(name), [], name)

    def test_schema_columns_match_naming_sheet(self):
        expected = {
            "codemender_findings": ["finding_id", "issue_id", "session_id", "repository",
                                    "commit_sha", "file_path", "line_number", "title",
                                    "description", "vulnerability_type", "cwe_id", "severity",
                                    "status", "patch_ref", "pr_url", "wiz_issue_id",
                                    "created_at", "updated_at"],
            "security_events": ["insert_id", "event_timestamp", "ingest_timestamp",
                                "event_type", "source", "severity", "project_id",
                                "resource_type", "resource_name", "principal", "repository",
                                "commit_sha", "issue_id", "session_id", "run_id", "status",
                                "summary", "log_name", "raw_payload"],
            "sandbox_runs": ["run_id", "execution_name", "repository", "commit_sha",
                             "patch_ref", "issue_id", "poc_test", "started_at", "finished_at",
                             "poc_before", "poc_after", "patch_applied", "unit_tests_passed",
                             "tests_total", "tests_failed", "verdict", "log_excerpt"],
            "code_to_cloud_map": ["resource_id", "resource_name", "cloud_platform", "image",
                                  "image_digest", "base_image", "repository",
                                  "dockerfile_path", "terraform_path", "commit_sha",
                                  "updated_at"],
            "ingestion_errors": ["received_at", "message_id", "insert_id", "error",
                                 "raw_message"],
            "scc_findings": ["finding_id", "source_id", "event_time", "finding", "resource"],
            "model_armor_logs": ["timestamp", "insertId", "logName", "severity", "resource",
                                 "jsonPayload"],
            "vpcsc_logs": ["timestamp", "insertId", "logName", "severity", "resource",
                           "protopayload_auditlog"],
        }
        for name, cols in expected.items():
            self.assertEqual([f["name"] for f in L.load_schema(name)], cols, name)
        req = {name: [f["name"] for f in L.load_schema(name) if f["mode"] == "REQUIRED"]
               for name in L.TABLES}
        self.assertEqual(req["codemender_findings"], ["finding_id", "created_at"])
        self.assertEqual(req["security_events"],
                         ["insert_id", "event_timestamp", "ingest_timestamp", "event_type"])
        self.assertEqual(req["sandbox_runs"], ["run_id"])
        self.assertEqual(req["code_to_cloud_map"], ["resource_id"])
        self.assertEqual(req["ingestion_errors"], ["received_at"])

    def test_validator_rejects_bad_rows(self):
        schema = [
            {"name": "id", "type": "STRING", "mode": "REQUIRED"},
            {"name": "n", "type": "INT64", "mode": "NULLABLE"},
            {"name": "ok", "type": "BOOL", "mode": "NULLABLE"},
            {"name": "ts", "type": "TIMESTAMP", "mode": "NULLABLE"},
            {"name": "tags", "type": "STRING", "mode": "REPEATED"},
            {"name": "rec", "type": "RECORD", "mode": "NULLABLE",
             "fields": [{"name": "x", "type": "STRING", "mode": "REQUIRED"}]},
        ]
        good = {"id": "a", "n": 1, "ok": True, "ts": "2026-10-01T00:00:00Z",
                "tags": ["a", "b"], "rec": {"x": "y"}}
        self.assertEqual(L.validate_row(good, schema), [])
        cases = [
            {"n": 1},                                   # REQUIRED missing
            {"id": "a", "n": "1"},                      # INT64 as string
            {"id": "a", "n": True},                     # bool is not INT64
            {"id": "a", "ok": "true"},                  # BOOL as string
            {"id": "a", "ts": "yesterday"},             # bad timestamp
            {"id": "a", "tags": "a"},                   # REPEATED not list
            {"id": "a", "tags": ["a", 1]},              # wrong element type
            {"id": "a", "rec": {}},                     # nested REQUIRED missing
            {"id": "a", "rec": "x"},                    # RECORD not object
            {"id": "a", "extra": 1},                    # unknown field
        ]
        for bad in cases:
            self.assertTrue(L.validate_row(bad, schema), bad)

    def test_json_text_columns_are_json(self):
        for r in rows("security_events"):
            entry = json.loads(r["raw_payload"])
            self.assertEqual(entry["insertId"], r["insert_id"])
            self.assertEqual(entry["logName"], r["log_name"])
            self.assertEqual(entry["timestamp"], r["event_timestamp"])
        for r in rows("vpcsc_logs"):
            meta = json.loads(r["protopayload_auditlog"]["metadataJson"])
            self.assertIn(meta["violationReason"], {"RESOURCES_NOT_IN_SAME_SERVICE_PERIMETER",
                                                    "NO_MATCHING_ACCESS_LEVEL"})
            self.assertEqual(meta["securityPolicyInfo"]["servicePerimeterName"],
                             "accessPolicies/123456789/servicePerimeters/security_lab_perimeter")


class ConsistencyTests(unittest.TestCase):
    def setUp(self):
        self.findings = {r["finding_id"]: r for r in rows("codemender_findings")}
        self.events = rows("security_events")
        self.runs = {r["run_id"]: r for r in rows("sandbox_runs")}

    def test_core_findings(self):
        expected = {"CM-0001": ("app/db.py", "CWE-89", "wiz-issue-0001"),
                    "CM-0002": ("app/receipts.py", "CWE-22", "wiz-issue-0002"),
                    "CM-0003": ("terraform/main.tf", "CWE-250", "wiz-issue-0003"),
                    "CM-0004": ("Dockerfile", "CWE-1104", "wiz-issue-0004")}
        for fid, (path, cwe, wiz) in expected.items():
            f = self.findings[fid]
            self.assertEqual((f["file_path"], f["cwe_id"], f["wiz_issue_id"]), (path, cwe, wiz))
            self.assertEqual((f["repository"], f["commit_sha"]), (REPO, COMMIT))
        others = [f for f in self.findings.values() if f["repository"] != REPO]
        self.assertGreaterEqual(len(others), 4)
        allowed = {"DETECTED", "OPEN", "PATCH_GENERATED", "VERIFIED", "APPLIED", "FIXED",
                   "FAILED", "FALSE_POSITIVE"}
        self.assertTrue(all(f["status"] in allowed for f in self.findings.values()))

    def test_event_issue_ids_exist_in_findings(self):
        for e in self.events:
            if e["issue_id"]:
                self.assertIn(e["issue_id"], self.findings, e["insert_id"])

    def test_event_types_and_sources(self):
        types = {"CODEMENDER_SCAN_STARTED", "CODEMENDER_SCAN_COMPLETED", "CODEMENDER_FINDING",
                 "CODEMENDER_PATCH", "SANDBOX_RESULT", "IAM_POLICY_CHANGE", "OTHER_SECURITY"}
        for e in self.events:
            self.assertIn(e["event_type"], types)
            self.assertIn(e["source"], {"codemender", "sandbox", "cloud_audit"})
        ids = [e["insert_id"] for e in self.events]
        self.assertEqual(len(ids), len(set(ids)))
        seen = {e["event_type"] for e in self.events}
        self.assertTrue({"CODEMENDER_SCAN_STARTED", "CODEMENDER_SCAN_COMPLETED",
                         "CODEMENDER_FINDING", "SANDBOX_RESULT",
                         "IAM_POLICY_CHANGE"} <= seen)

    def test_sandbox_runs_match_events(self):
        sbx_events = {e["run_id"]: e for e in self.events if e["event_type"] == "SANDBOX_RESULT"}
        self.assertEqual(set(sbx_events), set(self.runs))
        for run_id, r in self.runs.items():
            e = sbx_events[run_id]
            self.assertEqual(e["status"], r["verdict"])
            self.assertEqual(e["issue_id"], r["issue_id"])
            payload = json.loads(e["raw_payload"])["jsonPayload"]
            for k in ("execution_name", "patch_ref", "verdict", "started_at", "finished_at"):
                self.assertEqual(payload[k], r[k], (run_id, k))
            self.assertIn(r["issue_id"], self.findings)

    def test_cm0001_failed_then_verified(self):
        cm1 = sorted((r for r in self.runs.values() if r["issue_id"] == "CM-0001"),
                     key=lambda r: r["started_at"])
        self.assertEqual([r["verdict"] for r in cm1], ["PATCH_FAILED", "PATCH_VERIFIED"])
        self.assertEqual(self.findings["CM-0001"]["patch_ref"], cm1[-1]["patch_ref"])
        self.assertEqual(self.findings["CM-0001"]["status"], "VERIFIED")

    def test_verdict_rules(self):
        for r in self.runs.values():
            if r["poc_before"] != "EXPLOITABLE":
                want = "POC_NOT_REPRODUCED"
            elif r["poc_after"] == "NOT_EXPLOITABLE" and r["unit_tests_passed"]:
                want = "PATCH_VERIFIED"
            else:
                want = "PATCH_FAILED"
            self.assertEqual(r["verdict"], want, r["run_id"])

    def test_patch_refs_follow_bucket_layout(self):
        prefix = "gs://your-gcp-project-id-sandbox-inputs/patches/"
        for r in list(self.runs.values()) + list(self.findings.values()):
            ref = r["patch_ref"]
            if ref and ref != "none":
                self.assertTrue(ref.startswith(prefix + r["issue_id"] + "/"), ref)
                self.assertTrue(ref.endswith(".diff"), ref)

    def test_iam_change(self):
        iam = [e for e in self.events if e["event_type"] == "IAM_POLICY_CHANGE"]
        self.assertEqual(len(iam), 1)
        delta = json.loads(iam[0]["raw_payload"])["protoPayload"]["serviceData"]
        binding = delta["policyDelta"]["bindingDeltas"][0]
        self.assertEqual(binding["role"], "roles/editor")
        self.assertIn("payment-service-sa@", binding["member"])

    def test_code_to_cloud(self):
        c2c = {r["resource_id"]: r for r in rows("code_to_cloud_map")}
        pay = c2c[RUN_RES]
        self.assertEqual(pay["base_image"], "python:3.8-slim-buster")
        self.assertEqual(pay["dockerfile_path"], "Dockerfile")
        self.assertEqual(pay["terraform_path"], "terraform/main.tf")
        self.assertEqual(pay["commit_sha"], COMMIT)
        self.assertTrue(pay["image"].startswith(
            "us-central1-docker.pkg.dev/your-gcp-project-id/security-lab/payment-service@sha256:"))
        self.assertTrue(pay["image"].endswith(pay["image_digest"]))
        self.assertTrue(any(r["repository"] == "your-github-org/inventory-api"
                            for r in c2c.values()))
        repos = {f["repository"] for f in self.findings.values()}
        for r in c2c.values():
            self.assertIn(r["repository"], repos)

    def test_wiz_mocks_reference_same_resources(self):
        c2c_ids = {r["resource_id"] for r in rows("code_to_cloud_map")}
        issues = read_json("wiz_mock/issues.json")
        self.assertIn("verify against your tenant's schema", issues["_comment"])
        nodes = issues["data"]["issuesV2"]["nodes"]
        self.assertEqual([n["id"] for n in nodes], [f"wiz-issue-{i:04d}" for i in range(1, 5)])
        for n in nodes:
            self.assertIn(n["entitySnapshot"]["externalId"], c2c_ids)
            cm = issues["_lab_mapping"][n["id"]]
            self.assertEqual(self.findings[cm]["wiz_issue_id"], n["id"])
        digest = next(r["image_digest"] for r in rows("code_to_cloud_map")
                      if r["resource_id"] == RUN_RES)
        vuln = read_json("wiz_mock/vulnerability_findings.json")
        node = vuln["data"]["vulnerabilityFindings"]["nodes"][0]
        self.assertEqual(node["vulnerableAsset"]["imageId"], digest)
        self.assertEqual(node["severity"], "CRITICAL")
        c2c = read_json("wiz_mock/code_to_cloud.json")
        ents = c2c["data"]["graphSearch"]["nodes"][0]["entities"]
        self.assertEqual(ents[0]["name"], REPO)
        self.assertEqual(ents[-1]["properties"]["externalId"], RUN_RES)
        for rel in ("identities.json", "code_to_cloud.json", "vulnerability_findings.json"):
            self.assertIn("verify against your tenant's schema",
                          read_json("wiz_mock/" + rel)["_comment"])

    def test_scc_model_armor_vpcsc_story(self):
        scc = rows("scc_findings")
        cats = {r["finding"]["category"] for r in scc}
        self.assertTrue({"OPEN_FIREWALL", "PUBLIC_BUCKET_ACL", "PRIMITIVE_ROLES_USED"} <= cats)
        self.assertTrue(all("illustrative" in r["finding"]["description"] for r in scc))
        ma = rows("model_armor_logs")
        blocked = [r for r in ma if r["jsonPayload"]["filter_match_state"] == "MATCH_FOUND"
                   and "pi_and_jailbreak" in (r["jsonPayload"]["matched_filters"] or "")]
        self.assertTrue(blocked)
        vpcsc = rows("vpcsc_logs")
        bq = [r for r in vpcsc if r["protopayload_auditlog"]["serviceName"]
              == "bigquery.googleapis.com"]
        self.assertTrue(bq)
        self.assertTrue(all("example.com" not in r["protopayload_auditlog"]
                            ["authenticationInfo"]["principalEmail"] for r in bq))

    def test_log_entry_samples(self):
        d = os.path.join(ROOT, "log_entries")
        files = sorted(f for f in os.listdir(d) if f.endswith(".json"))
        self.assertGreaterEqual(len(files), 4)
        kinds = set()
        for f in files:
            entry = read_json("log_entries/" + f)
            self.assertTrue(entry["insertId"].startswith("sample-"))
            self.assertTrue(entry["logName"].startswith("projects/your-gcp-project-id/logs/"))
            if "jsonPayload" in entry:
                kinds.add(entry["jsonPayload"]["event_type"])
                iid = entry["jsonPayload"].get("issue_id")
                self.assertIn(iid, self.findings)
            else:
                kinds.add(entry["protoPayload"]["methodName"])
        self.assertEqual(kinds, {"CODEMENDER_FINDING", "SANDBOX_RESULT", "SetIamPolicy"})


class ShiftTests(unittest.TestCase):
    def test_offset_moves_newest_to_now(self):
        tables = {s: (L.load_schema(s), L.load_rows(s)) for s in L.TABLES}
        now = dt.datetime(2027, 1, 15, 12, 0, 0, tzinfo=UTC)
        offset = L.compute_offset(tables, now)
        newest = L.newest_timestamp(tables)
        self.assertEqual(newest + offset, now)
        prepared, off2, errors = L.prepare(list(L.TABLES), shift=True, now=now)
        self.assertEqual(errors, [])
        self.assertEqual(off2, offset)
        shifted = {s: prepared[s] for s in prepared}
        self.assertEqual(L.newest_timestamp(shifted), now)
        for s, (schema, rws) in prepared.items():
            for r in rws:
                self.assertEqual(L.validate_row(r, schema), [], s)

    def test_shift_preserves_gaps_and_nested_and_json_text(self):
        now = dt.datetime(2027, 1, 15, 12, 0, 0, tzinfo=UTC)
        prepared, offset, _ = L.prepare(["security_events", "scc_findings", "sandbox_runs"],
                                        shift=True, now=now)
        orig = L.load_rows("security_events")
        new = prepared["security_events"][1]
        for o, n in zip(orig, new):
            self.assertEqual(L.parse_ts(n["event_timestamp"]) - L.parse_ts(o["event_timestamp"]),
                             offset)
            self.assertEqual(json.loads(n["raw_payload"])["timestamp"], n["event_timestamp"])
        o_scc = L.load_rows("scc_findings")[0]
        n_scc = prepared["scc_findings"][1][0]
        self.assertEqual(L.parse_ts(n_scc["finding"]["create_time"])
                         - L.parse_ts(o_scc["finding"]["create_time"]), offset)
        # sandbox_runs and the SANDBOX_RESULT payload stay in step
        runs = {r["run_id"]: r for r in prepared["sandbox_runs"][1]}
        for e in new:
            if e["event_type"] == "SANDBOX_RESULT":
                p = json.loads(e["raw_payload"])["jsonPayload"]
                self.assertEqual(p["finished_at"], runs[e["run_id"]]["finished_at"])

    def test_only_uses_global_offset(self):
        now = dt.datetime(2027, 1, 15, 12, 0, 0, tzinfo=UTC)
        _, off_all, _ = L.prepare(list(L.TABLES), now=now)
        _, off_one, _ = L.prepare(["code_to_cloud_map"], now=now)
        self.assertEqual(off_all, off_one)

    def test_no_shift_keeps_rows(self):
        prepared, offset, _ = L.prepare(["codemender_findings"], shift=False)
        self.assertEqual(offset, dt.timedelta(0))
        self.assertEqual(prepared["codemender_findings"][1], L.load_rows("codemender_findings"))

    def test_seven_day_window_after_shift(self):
        now = dt.datetime.now(UTC)
        prepared, _, _ = L.prepare(["security_events"], now=now)
        recent = [r for r in prepared["security_events"][1]
                  if L.parse_ts(r["event_timestamp"]) >= now - dt.timedelta(days=7)]
        ids = {r["issue_id"] for r in recent}
        self.assertTrue({"CM-0001", "CM-0002", "CM-0003", "CM-0004"} <= ids)

    def test_project_substitution(self):
        prepared, _, _ = L.prepare(["code_to_cloud_map"], shift=False, project="acme-sec-lab")
        text = json.dumps(prepared["code_to_cloud_map"][1])
        self.assertNotIn("your-gcp-project-id", text)
        self.assertIn("acme-sec-lab", text)


class CliTests(unittest.TestCase):
    def test_dry_run_in_process(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = L.main(["--project", "your-gcp-project-id", "--dry-run"])
        self.assertEqual(rc, 0)
        out = buf.getvalue()
        self.assertIn("Schema validation OK", out)
        self.assertIn("Dry run complete", out)
        self.assertIn("security_lab.security_events", out)
        self.assertNotIn("google.cloud.bigquery", sys.modules)

    def test_dry_run_only_and_replace(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = L.main(["--dry-run", "--no-shift", "--replace", "--only", "sandbox_runs",
                         "--only", "cloudaudit_googleapis_com_policy"])
        self.assertEqual(rc, 0)
        out = buf.getvalue()
        self.assertIn("WRITE_TRUNCATE", out)
        self.assertIn("disabled", out)
        self.assertNotIn("codemender.findings", out)

    def test_unknown_table(self):
        with self.assertRaises(SystemExit):
            L.resolve_table("nope")

    def test_dry_run_subprocess(self):
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        proc = subprocess.run([sys.executable, os.path.join(ROOT, "load_seed_data.py"),
                               "--project", "your-gcp-project-id", "--dry-run"],
                              capture_output=True, text=True, env=env, cwd=ROOT, timeout=60)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("Dry run complete", proc.stdout)

    def test_shell_scripts_parse(self):
        for rel in ("load_seed_data.sh", "log_entries/write_sample_logs.sh"):
            proc = subprocess.run(["bash", "-n", os.path.join(ROOT, rel)],
                                  capture_output=True, text=True, timeout=30)
            self.assertEqual(proc.returncode, 0, proc.stderr)


if __name__ == "__main__":
    unittest.main()
