"""Shared test helpers. Works under `unittest discover -s tests` and under pytest."""

from __future__ import annotations

import base64
import json
import logging
import os
import sys
import types
from typing import Any, Dict, List, Optional

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(TESTS_DIR)
FIXTURES_DIR = os.path.join(TESTS_DIR, "fixtures")

for _path in (ROOT_DIR, TESTS_DIR):
    if _path not in sys.path:
        sys.path.insert(0, _path)

# Keep test output readable.
logging.getLogger("security-log-ingestion").setLevel(logging.CRITICAL)


def install_bigquery_stub() -> bool:
    """Install a minimal google.cloud.bigquery into sys.modules if the real one is missing.

    Returns True if a stub was installed.
    """
    try:
        import google.cloud.bigquery  # noqa: F401

        return False
    except ImportError:
        pass

    import google

    try:
        import google.cloud as google_cloud
    except ImportError:
        google_cloud = types.ModuleType("google.cloud")
        google_cloud.__path__ = []  # type: ignore[attr-defined]
        sys.modules["google.cloud"] = google_cloud
        google.cloud = google_cloud  # type: ignore[attr-defined]

    stub = types.ModuleType("google.cloud.bigquery")

    class Client:  # pragma: no cover - trivial
        instances: List["Client"] = []

        def __init__(self, project: Optional[str] = None, **kwargs: Any) -> None:
            self.project = project
            self.kwargs = kwargs
            self.calls: List[Dict[str, Any]] = []
            Client.instances.append(self)

        def insert_rows_json(self, table: Any, json_rows: Any, row_ids: Any = None, **kwargs: Any) -> list:
            self.calls.append({"table": table, "rows": json_rows, "row_ids": row_ids})
            return []

    stub.Client = Client  # type: ignore[attr-defined]
    stub.__stub__ = True  # type: ignore[attr-defined]
    sys.modules["google.cloud.bigquery"] = stub
    google_cloud.bigquery = stub  # type: ignore[attr-defined]
    return True


def load_fixture(name: str) -> Dict[str, Any]:
    with open(os.path.join(FIXTURES_DIR, name), encoding="utf-8") as handle:
        return json.load(handle)


def push_envelope(data: Any, message_id: str = "msg-1") -> Dict[str, Any]:
    """Build a Pub/Sub push envelope. `data` may be a dict, str or bytes."""
    if isinstance(data, dict):
        raw = json.dumps(data).encode("utf-8")
    elif isinstance(data, str):
        raw = data.encode("utf-8")
    else:
        raw = data
    return {
        "message": {
            "data": base64.b64encode(raw).decode("ascii"),
            "messageId": message_id,
            "message_id": message_id,
            "publishTime": "2026-10-20T15:04:07Z",
            "attributes": {},
        },
        "subscription": "projects/your-gcp-project-id/subscriptions/security-logs-push",
    }


class HttpError(Exception):
    """Mimics google.api_core exceptions, which carry an integer `code`."""

    def __init__(self, code: int, message: str = "error") -> None:
        super().__init__(message)
        self.code = code


class FakeBigQueryClient:
    """Records insert_rows_json calls. Per-table behavior via `fail`.

    fail[table_suffix] may be an exception instance (raised) or a list (returned as row errors).
    """

    def __init__(self) -> None:
        self.calls: List[Dict[str, Any]] = []
        self.fail: Dict[str, Any] = {}

    def insert_rows_json(self, table: str, json_rows: list, row_ids: Any = None) -> list:
        self.calls.append({"table": table, "rows": json_rows, "row_ids": row_ids})
        for suffix, behavior in self.fail.items():
            if table.endswith(suffix):
                if isinstance(behavior, BaseException):
                    raise behavior
                return behavior
        return []

    def tables(self) -> List[str]:
        return [call["table"] for call in self.calls]

    def calls_for(self, suffix: str) -> List[Dict[str, Any]]:
        return [call for call in self.calls if call["table"].endswith(suffix)]
