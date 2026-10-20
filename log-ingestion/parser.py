"""Pure functions that turn a Cloud Logging LogEntry (dict) into BigQuery rows.

Nothing here talks to the network. Input values are never trusted: ints, bools
and timestamps are coerced, strings are length-capped, and raw_payload is
size-capped while staying valid JSON.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from urllib.parse import unquote

# raw_payload cap in UTF-8 bytes. Streaming inserts allow rows up to 10 MB;
# 100 KB keeps rows small and query costs predictable.
MAX_RAW_PAYLOAD_BYTES = 100_000
MAX_STRING_CHARS = 4_096
MAX_TEXT_CHARS = 20_000  # description, summary, log_excerpt

CODEMENDER_LOG_ID = "codemender"
SANDBOX_JOB_NAME = "codemender-sandbox"

CODEMENDER_EVENT_TYPES = frozenset(
    {
        "CODEMENDER_SCAN_STARTED",
        "CODEMENDER_SCAN_COMPLETED",
        "CODEMENDER_FINDING",
        "CODEMENDER_PATCH",
    }
)
SANDBOX_RESULT = "SANDBOX_RESULT"
IAM_POLICY_CHANGE = "IAM_POLICY_CHANGE"
OTHER_SECURITY = "OTHER_SECURITY"

FINDING_STATUSES = frozenset(
    {
        "DETECTED",
        "OPEN",
        "PATCH_GENERATED",
        "VERIFIED",
        "APPLIED",
        "FIXED",
        "FAILED",
        "FALSE_POSITIVE",
    }
)
POC_STATES = frozenset({"EXPLOITABLE", "NOT_EXPLOITABLE", "ERROR"})
VERDICTS = frozenset({"PATCH_VERIFIED", "PATCH_FAILED", "POC_NOT_REPRODUCED", "ERROR"})

_TRUE = frozenset({"true", "t", "yes", "y", "1"})
_FALSE = frozenset({"false", "f", "no", "n", "0"})

_TS_RE = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})[T ](?P<time>\d{2}:\d{2}:\d{2})"
    r"(?:\.(?P<frac>\d+))?\s*(?P<tz>Z|z|UTC|[+-]\d{2}:?\d{2})?$"
)


class ParseError(ValueError):
    """The message or LogEntry cannot be turned into rows. Not retryable."""


# --------------------------------------------------------------------------
# Coercion helpers
# --------------------------------------------------------------------------


def coerce_str(value: Any, max_chars: int = MAX_STRING_CHARS) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, str):
        text = value
    elif isinstance(value, bool):
        text = "true" if value else "false"
    elif isinstance(value, (int, float)):
        text = str(value)
    else:
        try:
            text = json.dumps(value, sort_keys=True, default=str)
        except (TypeError, ValueError):
            text = str(value)
    if text == "":
        return None
    if len(text) > max_chars:
        text = text[:max_chars]
    return text


def coerce_int(value: Any) -> Optional[int]:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value) if value.is_integer() else None
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            return int(text)
        except ValueError:
            try:
                number = float(text)
            except ValueError:
                return None
            return int(number) if number.is_integer() else None
    return None


def coerce_bool(value: Any) -> Optional[bool]:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        if value in (0, 1):
            return bool(value)
        return None
    if isinstance(value, str):
        text = value.strip().lower()
        if text in _TRUE:
            return True
        if text in _FALSE:
            return False
    return None


def coerce_enum(value: Any, allowed: frozenset) -> Optional[str]:
    text = coerce_str(value)
    if text is None:
        return None
    text = text.strip().upper()
    return text if text in allowed else None


def parse_timestamp(value: Any) -> Optional[str]:
    """Return a UTC timestamp string BigQuery accepts, or None.

    Accepts RFC 3339 strings (including Cloud Logging's nanosecond precision),
    and epoch seconds or milliseconds as numbers or numeric strings.
    """
    if value is None or isinstance(value, bool):
        return None
    dt: Optional[datetime] = None
    if isinstance(value, (int, float)):
        dt = _from_epoch(float(value))
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        match = _TS_RE.match(text)
        if match:
            frac = (match.group("frac") or "0")[:6].ljust(6, "0")
            tz = match.group("tz") or "Z"
            if tz in ("Z", "z", "UTC"):
                tz = "+00:00"
            elif ":" not in tz:
                tz = tz[:3] + ":" + tz[3:]
            try:
                dt = datetime.fromisoformat(
                    f"{match.group('date')}T{match.group('time')}.{frac}{tz}"
                )
            except ValueError:
                return None
        else:
            try:
                dt = _from_epoch(float(text))
            except ValueError:
                return None
    if dt is None:
        return None
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _from_epoch(seconds: float) -> Optional[datetime]:
    if seconds != seconds:  # NaN
        return None
    if abs(seconds) > 1e11:  # milliseconds
        seconds = seconds / 1000.0
    try:
        return datetime.fromtimestamp(seconds, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def truncate_json_text(text: str, max_bytes: int = MAX_RAW_PAYLOAD_BYTES) -> str:
    """Cap text at max_bytes UTF-8 bytes.

    If the text is too long it is replaced by a small JSON object holding a
    prefix, so raw_payload is always valid JSON text.
    """
    encoded = text.encode("utf-8")
    if len(encoded) <= max_bytes:
        return text
    budget = max(max_bytes - 256, 0)
    while True:
        prefix = encoded[:budget].decode("utf-8", errors="ignore")
        wrapped = json.dumps(
            {"truncated": True, "original_bytes": len(encoded), "prefix": prefix},
            ensure_ascii=False,
        )
        if len(wrapped.encode("utf-8")) <= max_bytes or budget == 0:
            return wrapped
        # JSON escaping grew the text; shrink and try again.
        budget = max(int(budget * 0.8), 0)


def to_raw_payload(entry: Any, max_bytes: int = MAX_RAW_PAYLOAD_BYTES) -> str:
    try:
        text = json.dumps(entry, sort_keys=True, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        text = json.dumps({"unserializable": str(entry)})
    return truncate_json_text(text, max_bytes)


# --------------------------------------------------------------------------
# LogEntry accessors
# --------------------------------------------------------------------------


def _dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def log_id(log_name: Any) -> Optional[str]:
    """`projects/p/logs/run.googleapis.com%2Fstdout` -> `run.googleapis.com/stdout`."""
    if not isinstance(log_name, str) or "/logs/" not in log_name:
        return None
    return unquote(log_name.split("/logs/", 1)[1])


def json_payload(entry: Dict[str, Any]) -> Dict[str, Any]:
    """jsonPayload, or textPayload parsed as a JSON object if it is one."""
    payload = entry.get("jsonPayload")
    if isinstance(payload, dict):
        return payload
    text = entry.get("textPayload")
    if isinstance(text, str) and text.lstrip().startswith("{"):
        try:
            parsed = json.loads(text)
        except ValueError:
            return {}
        if isinstance(parsed, dict):
            return parsed
    return {}


def _project_id(entry: Dict[str, Any]) -> Optional[str]:
    labels = _dict(_dict(entry.get("resource")).get("labels"))
    if labels.get("project_id"):
        return coerce_str(labels.get("project_id"))
    name = entry.get("logName")
    if isinstance(name, str) and name.startswith("projects/"):
        parts = name.split("/")
        if len(parts) > 1 and parts[1]:
            return coerce_str(parts[1])
    return None


def _is_codemender(entry: Dict[str, Any]) -> bool:
    return log_id(entry.get("logName")) == CODEMENDER_LOG_ID


def _is_sandbox_result(entry: Dict[str, Any]) -> bool:
    resource = _dict(entry.get("resource"))
    labels = _dict(resource.get("labels"))
    if resource.get("type") != "cloud_run_job" or labels.get("job_name") != SANDBOX_JOB_NAME:
        return False
    event_type = coerce_str(json_payload(entry).get("event_type"))
    return event_type is not None and event_type.strip().upper() == SANDBOX_RESULT


def _is_set_iam_policy(entry: Dict[str, Any]) -> bool:
    proto = _dict(entry.get("protoPayload"))
    method = proto.get("methodName")
    if not isinstance(method, str):
        return False
    # Matches "SetIamPolicy" and service-qualified forms such as
    # "google.iam.admin.v1.SetIAMPolicy".
    return method.lower().endswith("setiampolicy")


def _codemender_event_type(payload: Dict[str, Any]) -> Optional[str]:
    raw = coerce_str(payload.get("event_type"))
    if raw is None:
        return None
    value = raw.strip().upper()
    if not value.startswith("CODEMENDER_"):
        value = "CODEMENDER_" + value
    return value if value in CODEMENDER_EVENT_TYPES else None


# --------------------------------------------------------------------------
# Classification
# --------------------------------------------------------------------------


def classify(entry: Dict[str, Any]) -> str:
    """Return the security_events.event_type for a LogEntry."""
    if not isinstance(entry, dict):
        return OTHER_SECURITY
    if _is_codemender(entry):
        return _codemender_event_type(json_payload(entry)) or OTHER_SECURITY
    if _is_sandbox_result(entry):
        return SANDBOX_RESULT
    if _is_set_iam_policy(entry):
        return IAM_POLICY_CHANGE
    return OTHER_SECURITY


def source_for(entry: Dict[str, Any]) -> Optional[str]:
    if _is_codemender(entry):
        return "codemender"
    resource = _dict(entry.get("resource"))
    if (
        resource.get("type") == "cloud_run_job"
        and _dict(resource.get("labels")).get("job_name") == SANDBOX_JOB_NAME
    ):
        return "sandbox"
    log = log_id(entry.get("logName")) or ""
    if log.startswith("cloudaudit.googleapis.com/") or isinstance(entry.get("protoPayload"), dict):
        return "cloud_audit"
    return None


# --------------------------------------------------------------------------
# Row builders
# --------------------------------------------------------------------------


def event_timestamp(entry: Dict[str, Any]) -> str:
    ts = parse_timestamp(entry.get("timestamp")) or parse_timestamp(entry.get("receiveTimestamp"))
    if ts is None:
        raise ParseError("LogEntry has no parseable timestamp or receiveTimestamp")
    return ts


def insert_id(entry: Dict[str, Any]) -> str:
    value = coerce_str(entry.get("insertId"), max_chars=1_024)
    if value is None or not value.strip():
        raise ParseError("LogEntry has no insertId")
    return value.strip()


def _severity(entry: Dict[str, Any], payload: Dict[str, Any], prefer_payload: bool) -> Optional[str]:
    candidates = (payload.get("severity"), entry.get("severity"))
    if not prefer_payload:
        candidates = candidates[::-1]
    for candidate in candidates:
        text = coerce_str(candidate, max_chars=32)
        if text and text.strip():
            return text.strip().upper()
    return None


def _iam_summary(proto: Dict[str, Any]) -> str:
    principal = _dict(proto.get("authenticationInfo")).get("principalEmail") or "unknown principal"
    method = proto.get("methodName") or "SetIamPolicy"
    resource = proto.get("resourceName") or "unknown resource"
    parts = [f"{principal} called {method} on {resource}"]
    deltas = _dict(_dict(proto.get("serviceData")).get("policyDelta")).get("bindingDeltas")
    if not isinstance(deltas, list):
        deltas = _dict(_dict(proto.get("metadata")).get("datasetChange")).get("bindingDeltas")
    if isinstance(deltas, list):
        changes = []
        for delta in deltas[:10]:
            delta = _dict(delta)
            changes.append(
                f"{delta.get('action', '?')} {delta.get('role', '?')} {delta.get('member', '?')}"
            )
        if changes:
            parts.append("; ".join(changes))
    return ": ".join(parts)


def build_security_event(
    entry: Dict[str, Any], ingest_timestamp: Optional[str] = None
) -> Dict[str, Any]:
    """Build a security_events row. Raises ParseError if required fields are missing."""
    if not isinstance(entry, dict):
        raise ParseError("LogEntry is not a JSON object")
    event_type = classify(entry)
    source = source_for(entry)
    payload = json_payload(entry)
    proto = _dict(entry.get("protoPayload"))
    resource = _dict(entry.get("resource"))
    labels = _dict(resource.get("labels"))

    row: Dict[str, Any] = {
        "insert_id": insert_id(entry),
        "event_timestamp": event_timestamp(entry),
        "ingest_timestamp": parse_timestamp(ingest_timestamp) or utc_now(),
        "event_type": event_type,
        "source": source,
        "severity": _severity(entry, payload, prefer_payload=(source == "codemender")),
        "project_id": _project_id(entry),
        "resource_type": coerce_str(resource.get("type")),
        "resource_name": None,
        "principal": coerce_str(_dict(proto.get("authenticationInfo")).get("principalEmail")),
        "repository": coerce_str(payload.get("repository")),
        "commit_sha": coerce_str(payload.get("commit_sha")),
        "issue_id": coerce_str(payload.get("issue_id")),
        "session_id": coerce_str(payload.get("session_id")),
        "run_id": coerce_str(payload.get("run_id")),
        "status": coerce_str(payload.get("status")),
        "summary": None,
        "log_name": coerce_str(entry.get("logName")),
        "raw_payload": to_raw_payload(entry),
    }

    if source == "codemender":
        row["resource_name"] = coerce_str(payload.get("file_path"))
        summary = payload.get("message") or payload.get("title")
        if not summary and payload.get("finding_id"):
            summary = f"{event_type} {payload.get('finding_id')}"
        row["summary"] = coerce_str(summary, MAX_TEXT_CHARS)
    elif event_type == SANDBOX_RESULT:
        row["resource_name"] = coerce_str(labels.get("job_name"))
        verdict = coerce_enum(payload.get("verdict"), VERDICTS)
        row["status"] = verdict or row["status"]
        summary = payload.get("message")
        if not summary:
            summary = (
                f"Sandbox run {payload.get('run_id', '?')} for issue "
                f"{payload.get('issue_id', '?')}: {verdict or 'no verdict'}"
            )
        row["summary"] = coerce_str(summary, MAX_TEXT_CHARS)
    elif proto:
        row["resource_name"] = coerce_str(proto.get("resourceName"))
        if event_type == IAM_POLICY_CHANGE:
            row["summary"] = coerce_str(_iam_summary(proto), MAX_TEXT_CHARS)
        else:
            row["summary"] = coerce_str(proto.get("methodName"), MAX_TEXT_CHARS)
    else:
        row["summary"] = coerce_str(
            payload.get("message") or entry.get("textPayload"), MAX_TEXT_CHARS
        )
    return row


def build_sandbox_run(entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Build a sandbox_runs row, or None if this is not a usable SANDBOX_RESULT."""
    if classify(entry) != SANDBOX_RESULT:
        return None
    payload = json_payload(entry)
    run_id = coerce_str(payload.get("run_id"))
    if run_id is None:
        return None
    return {
        "run_id": run_id,
        "execution_name": coerce_str(payload.get("execution_name"))
        or coerce_str(_dict(entry.get("labels")).get("run.googleapis.com/execution_name")),
        "repository": coerce_str(payload.get("repository")),
        "commit_sha": coerce_str(payload.get("commit_sha")),
        "patch_ref": coerce_str(payload.get("patch_ref")),
        "issue_id": coerce_str(payload.get("issue_id")),
        "poc_test": coerce_str(payload.get("poc_test")),
        "started_at": parse_timestamp(payload.get("started_at")),
        "finished_at": parse_timestamp(payload.get("finished_at")),
        "poc_before": coerce_enum(payload.get("poc_before"), POC_STATES),
        "poc_after": coerce_enum(payload.get("poc_after"), POC_STATES),
        "patch_applied": coerce_bool(payload.get("patch_applied")),
        "unit_tests_passed": coerce_bool(payload.get("unit_tests_passed")),
        "tests_total": coerce_int(payload.get("tests_total")),
        "tests_failed": coerce_int(payload.get("tests_failed")),
        "verdict": coerce_enum(payload.get("verdict"), VERDICTS),
        "log_excerpt": coerce_str(payload.get("log_excerpt"), MAX_TEXT_CHARS),
    }


def build_finding(entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Build a codemender.findings row, or None if not a usable CODEMENDER_FINDING.

    Each finding event appends a row; created_at and updated_at are the event
    time. Missing or unknown status becomes DETECTED.
    """
    if classify(entry) != "CODEMENDER_FINDING":
        return None
    payload = json_payload(entry)
    finding_id = coerce_str(payload.get("finding_id"))
    if finding_id is None:
        return None
    ts = event_timestamp(entry)
    severity = coerce_str(payload.get("severity"), max_chars=32)
    return {
        "finding_id": finding_id,
        "issue_id": coerce_str(payload.get("issue_id")),
        "session_id": coerce_str(payload.get("session_id")),
        "repository": coerce_str(payload.get("repository")),
        "commit_sha": coerce_str(payload.get("commit_sha")),
        "file_path": coerce_str(payload.get("file_path")),
        "line_number": coerce_int(payload.get("line_number")),
        "title": coerce_str(payload.get("title")),
        "description": coerce_str(payload.get("description"), MAX_TEXT_CHARS),
        "vulnerability_type": coerce_str(payload.get("vulnerability_type")),
        "cwe_id": coerce_str(payload.get("cwe_id")),
        "severity": severity.strip().upper() if severity else None,
        "status": coerce_enum(payload.get("status"), FINDING_STATUSES) or "DETECTED",
        "patch_ref": coerce_str(payload.get("patch_ref")),
        "pr_url": coerce_str(payload.get("pr_url")),
        "wiz_issue_id": coerce_str(payload.get("wiz_issue_id")),
        "created_at": ts,
        "updated_at": ts,
    }


@dataclass
class ParsedEntry:
    insert_id: str
    event_type: str
    security_event: Dict[str, Any]
    sandbox_run: Optional[Dict[str, Any]] = None
    finding: Optional[Dict[str, Any]] = None


def parse_log_entry(entry: Any, ingest_timestamp: Optional[str] = None) -> ParsedEntry:
    """Build every row for one LogEntry. Raises ParseError if unusable."""
    if not isinstance(entry, dict):
        raise ParseError("LogEntry is not a JSON object")
    event = build_security_event(entry, ingest_timestamp)
    return ParsedEntry(
        insert_id=event["insert_id"],
        event_type=event["event_type"],
        security_event=event,
        sandbox_run=build_sandbox_run(entry),
        finding=build_finding(entry),
    )
