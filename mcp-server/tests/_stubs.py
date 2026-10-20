"""Minimal stand-ins for Google Cloud client libraries that may be missing locally.

Import this module before importing server or services. A stub is installed
only when the real library cannot be imported, so the tests run unchanged
in an environment where the real packages are installed.
"""

import os
import sys
import types

# Make `import server`, `import config` and `import services.*` work when the
# tests are started from mcp-server/ or from the repository root.
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


def _ensure_google_cloud_package() -> types.ModuleType:
    try:
        import google.cloud as gc  # noqa: F401

        return sys.modules["google.cloud"]
    except ImportError:
        google_pkg = sys.modules.get("google")
        if google_pkg is None:
            google_pkg = types.ModuleType("google")
            google_pkg.__path__ = []  # type: ignore[attr-defined]
            sys.modules["google"] = google_pkg
        cloud = types.ModuleType("google.cloud")
        cloud.__path__ = []  # type: ignore[attr-defined]
        sys.modules["google.cloud"] = cloud
        google_pkg.cloud = cloud  # type: ignore[attr-defined]
        return cloud


def _install_exceptions_stub(cloud: types.ModuleType) -> None:
    try:
        import google.cloud.exceptions  # noqa: F401
        return
    except ImportError:
        pass
    mod = types.ModuleType("google.cloud.exceptions")

    class GoogleCloudError(Exception):
        def __init__(self, message: str = "", *args):
            super().__init__(message, *args)
            self.message = message

    class NotFound(GoogleCloudError):
        pass

    mod.GoogleCloudError = GoogleCloudError
    mod.NotFound = NotFound
    sys.modules["google.cloud.exceptions"] = mod
    cloud.exceptions = mod  # type: ignore[attr-defined]


def _install_bigquery_stub(cloud: types.ModuleType) -> None:
    try:
        from google.cloud import bigquery  # noqa: F401
        return
    except ImportError:
        pass
    mod = types.ModuleType("google.cloud.bigquery")

    class Client:
        def __init__(self, project=None, *args, **kwargs):
            self.project = project or "stub-project"

        def query(self, *args, **kwargs):  # pragma: no cover - always mocked
            raise NotImplementedError("stub BigQuery client")

        def get_table(self, *args, **kwargs):  # pragma: no cover - always mocked
            raise NotImplementedError("stub BigQuery client")

    class ScalarQueryParameter:
        def __init__(self, name, type_, value):
            self.name = name
            self.type_ = type_
            self.value = value

        def __repr__(self):
            return f"ScalarQueryParameter({self.name!r}, {self.type_!r}, {self.value!r})"

    class ArrayQueryParameter:
        def __init__(self, name, array_type, values):
            self.name = name
            self.array_type = array_type
            self.values = list(values)

        def __repr__(self):
            return f"ArrayQueryParameter({self.name!r}, {self.array_type!r}, {self.values!r})"

    class QueryJobConfig:
        def __init__(self, query_parameters=None, **kwargs):
            self.query_parameters = list(query_parameters or [])
            for k, v in kwargs.items():
                setattr(self, k, v)

    class Row(dict):
        """dict-backed Row: supports row['col'], row.items(), row.get()."""

        def __init__(self, values=None, field_to_index=None):
            if isinstance(values, dict):
                super().__init__(values)
            elif field_to_index is not None:
                super().__init__({k: values[i] for k, i in field_to_index.items()})
            else:
                super().__init__()

    class SchemaField:
        def __init__(self, name, field_type, mode="NULLABLE", description=None, fields=()):
            self.name = name
            self.field_type = field_type
            self.mode = mode
            self.description = description
            self.fields = tuple(fields)

    mod.Client = Client
    mod.ScalarQueryParameter = ScalarQueryParameter
    mod.ArrayQueryParameter = ArrayQueryParameter
    mod.QueryJobConfig = QueryJobConfig
    mod.Row = Row
    mod.SchemaField = SchemaField
    sys.modules["google.cloud.bigquery"] = mod
    cloud.bigquery = mod  # type: ignore[attr-defined]


def _install_logging_stub(cloud: types.ModuleType) -> None:
    try:
        from google.cloud import logging_v2  # noqa: F401
        return
    except ImportError:
        pass
    mod = types.ModuleType("google.cloud.logging_v2")

    class Client:
        def __init__(self, project=None, *args, **kwargs):
            self.project = project

        def list_entries(self, *args, **kwargs):  # pragma: no cover - always mocked
            return iter(())

    class LogEntry:
        pass

    mod.Client = Client
    mod.LogEntry = LogEntry
    mod.DESCENDING = "timestamp desc"
    mod.ASCENDING = "timestamp asc"
    sys.modules["google.cloud.logging_v2"] = mod
    cloud.logging_v2 = mod  # type: ignore[attr-defined]
    try:
        from google.cloud import logging  # noqa: F401
    except ImportError:
        sys.modules["google.cloud.logging"] = mod
        cloud.logging = mod  # type: ignore[attr-defined]


def _drop_unreadable_ssl_cert_file() -> None:
    """httpx reads SSL_CERT_FILE when a client is created. Some sandboxes set it to a
    file the test process cannot read; tests never make real HTTPS calls, so drop it."""
    path = os.environ.get("SSL_CERT_FILE")
    if path:
        try:
            with open(path, "rb"):
                pass
        except OSError:
            os.environ.pop("SSL_CERT_FILE", None)


_drop_unreadable_ssl_cert_file()
_cloud = _ensure_google_cloud_package()
_install_exceptions_stub(_cloud)
_install_bigquery_stub(_cloud)
_install_logging_stub(_cloud)
