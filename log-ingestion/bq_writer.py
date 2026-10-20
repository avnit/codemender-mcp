"""BigQuery writes for security-log-ingestion.

Deduplication is best-effort at two levels:
1. An in-process LRU of recently written insertIds. It is per instance and is
   lost on restart, so it only catches redeliveries that land on the same
   Cloud Run instance.
2. BigQuery streaming insert row IDs (insertId). BigQuery drops repeats seen
   within roughly one minute, on a best-effort basis.
Neither is a guarantee. Use the MERGE query in README.md for exact dedupe.

google-cloud-bigquery is imported lazily so the module (and tests) load without it.
"""

from __future__ import annotations

import logging
import threading
from collections import OrderedDict
from typing import Any, Dict, List, Optional

from config import Settings
from parser import ParsedEntry, truncate_json_text, utc_now

logger = logging.getLogger(__name__)

MAX_RAW_MESSAGE_BYTES = 100_000
MAX_ERROR_CHARS = 4_096

# insert_rows_json per-row error reasons that are worth retrying.
TRANSIENT_ROW_REASONS = frozenset(
    {"backenderror", "internalerror", "timeout", "ratelimitexceeded", "quotaexceeded"}
)
# HTTP codes on raised exceptions that mean "this message will never succeed".
PERMANENT_HTTP_CODES = frozenset({400, 413})


class WriteError(Exception):
    pass


class TransientWriteError(WriteError):
    """Retry later: the handler returns 500 so Pub/Sub redelivers, then dead-letters."""


class PermanentWriteError(WriteError):
    """The row will never be accepted: the handler logs to ingestion_errors and returns 204."""


class RecentIds:
    """Thread-safe LRU set of recently written insertIds."""

    def __init__(self, capacity: int = 10_000) -> None:
        self.capacity = max(int(capacity), 1)
        self._items: "OrderedDict[str, None]" = OrderedDict()
        self._lock = threading.Lock()

    def __contains__(self, key: str) -> bool:
        with self._lock:
            if key in self._items:
                self._items.move_to_end(key)
                return True
            return False

    def add(self, key: str) -> None:
        with self._lock:
            self._items[key] = None
            self._items.move_to_end(key)
            while len(self._items) > self.capacity:
                self._items.popitem(last=False)

    def __len__(self) -> int:
        with self._lock:
            return len(self._items)


def classify_exception(exc: BaseException) -> WriteError:
    """Map a client exception to Transient/Permanent without importing google.api_core.

    400/413 are permanent. Everything else (429, 5xx, timeouts, connection
    errors, and also 403/404 which usually mean a deploy misconfiguration) is
    treated as transient so messages end up in the dead-letter topic instead
    of being dropped.
    """
    code = getattr(exc, "code", None)
    if isinstance(code, int) and code in PERMANENT_HTTP_CODES:
        return PermanentWriteError(f"{type(exc).__name__}: {exc}")
    return TransientWriteError(f"{type(exc).__name__}: {exc}")


def classify_row_errors(errors: List[Dict[str, Any]]) -> WriteError:
    reasons = set()
    for item in errors or []:
        for err in (item or {}).get("errors", []) or []:
            reason = str((err or {}).get("reason", "")).lower()
            if reason:
                reasons.add(reason)
    message = f"insert_rows_json row errors: {errors}"[:MAX_ERROR_CHARS]
    if reasons & TRANSIENT_ROW_REASONS:
        return TransientWriteError(message)
    return PermanentWriteError(message)


class BigQueryWriter:
    def __init__(
        self,
        settings: Settings,
        client: Any = None,
        recent_ids: Optional[RecentIds] = None,
    ) -> None:
        self.settings = settings
        self._client = client
        self._client_lock = threading.Lock()
        self.recent_ids = recent_ids if recent_ids is not None else RecentIds()

    @property
    def client(self) -> Any:
        if self._client is None:
            with self._client_lock:
                if self._client is None:
                    from google.cloud import bigquery  # lazy import

                    self._client = bigquery.Client(project=self.settings.project_id or None)
        return self._client

    def _insert(self, table_id: str, rows: List[Dict[str, Any]], row_ids: Optional[List[Optional[str]]]) -> None:
        try:
            if row_ids is None:
                errors = self.client.insert_rows_json(table_id, rows)
            else:
                errors = self.client.insert_rows_json(table_id, rows, row_ids=row_ids)
        except WriteError:
            raise
        except Exception as exc:  # noqa: BLE001 - classify every client failure
            raise classify_exception(exc) from exc
        if errors:
            raise classify_row_errors(errors)

    def is_duplicate(self, insert_id: str) -> bool:
        return insert_id in self.recent_ids

    def write_parsed(self, parsed: ParsedEntry) -> str:
        """Write all rows for one LogEntry. Returns "inserted" or "duplicate".

        Raises TransientWriteError or PermanentWriteError. On a transient
        failure partway through, a retry re-sends earlier rows with the same
        row IDs, so BigQuery's best-effort dedupe usually absorbs them.
        """
        if self.is_duplicate(parsed.insert_id):
            return "duplicate"
        self._insert(self.settings.security_events_table_id, [parsed.security_event], [parsed.insert_id])
        if parsed.sandbox_run is not None:
            self._insert(self.settings.sandbox_runs_table_id, [parsed.sandbox_run], [parsed.insert_id])
        if parsed.finding is not None:
            self._insert(self.settings.findings_table_id, [parsed.finding], [parsed.insert_id])
        self.recent_ids.add(parsed.insert_id)
        return "inserted"

    def write_ingestion_error(
        self,
        error: str,
        raw_message: Any = None,
        message_id: Optional[str] = None,
        insert_id: Optional[str] = None,
        received_at: Optional[str] = None,
    ) -> Dict[str, Any]:
        if isinstance(raw_message, bytes):
            raw_message = raw_message.decode("utf-8", errors="replace")
        row = {
            "received_at": received_at or utc_now(),
            "message_id": message_id,
            "insert_id": insert_id,
            "error": (error or "")[:MAX_ERROR_CHARS],
            "raw_message": truncate_json_text(raw_message, MAX_RAW_MESSAGE_BYTES)
            if isinstance(raw_message, str)
            else None,
        }
        # Pub/Sub redelivery reuses messageId, so it doubles as the row ID.
        self._insert(self.settings.ingestion_errors_table_id, [row], [message_id] if message_id else None)
        return row
