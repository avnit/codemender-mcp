#!/usr/bin/env python3
"""Load the lab seed data into BigQuery.

Usage (from seed-data/):
  python3 load_seed_data.py --project your-gcp-project-id --dry-run
  python3 load_seed_data.py --project your-gcp-project-id            # append, timestamps shifted
  python3 load_seed_data.py --project your-gcp-project-id --replace  # truncate, then load
  python3 load_seed_data.py --project your-gcp-project-id --only security_events

--dry-run validates every row against its schema and prints the planned actions. It needs
no GCP credentials and does not import google-cloud-bigquery.

Timestamps: the files use fixed dates in 2026-10. With --shift-to-now (default) every
TIMESTAMP column in every table is moved by the same offset so the newest row is "now".
ISO-8601 timestamps inside JSON-text columns (security_events.raw_payload,
ingestion_errors.raw_message, vpcsc metadataJson) are moved by the same offset.
"""
import argparse
import copy
import datetime as dt
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SCHEMA_DIR = os.path.join(HERE, "schemas")
PROJECT_PLACEHOLDER = "your-gcp-project-id"

# name -> (dataset env var, default dataset, table env var, default table, partition field,
#          clustering fields, created by a log sink)
TABLES = {
    "codemender_findings": ("BQ_DATASET", "codemender", "BQ_TABLE", "findings",
                            "created_at", None, False),
    "security_events": ("SECURITY_DATASET", "security_lab", "SECURITY_EVENTS_TABLE",
                        "security_events", "event_timestamp", ["event_type", "severity"], False),
    "sandbox_runs": ("SECURITY_DATASET", "security_lab", "SANDBOX_RUNS_TABLE", "sandbox_runs",
                     None, None, False),
    "code_to_cloud_map": ("SECURITY_DATASET", "security_lab", "CODE_TO_CLOUD_TABLE",
                          "code_to_cloud_map", None, None, False),
    "ingestion_errors": ("SECURITY_DATASET", "security_lab", "INGESTION_ERRORS_TABLE",
                         "ingestion_errors", None, None, False),
    "scc_findings": ("SCC_DATASET", "scc_export", "SCC_TABLE", "findings", None, None, False),
    "model_armor_logs": ("SECURITY_LOGS_DATASET", "security_logs", "MODEL_ARMOR_TABLE",
                         "modelarmor_googleapis_com_sanitize_operations", "timestamp", None,
                         True),
    "vpcsc_logs": ("SECURITY_LOGS_DATASET", "security_logs", "VPCSC_TABLE",
                   "cloudaudit_googleapis_com_policy", "timestamp", None, True),
}

# STRING columns that hold JSON text; timestamps inside them are shifted too.
JSON_TEXT_FIELDS = {"raw_payload", "raw_message", "metadataJson"}

TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d{1,6})?(Z|[+-]\d{2}:\d{2})?$")
TYPE_ALIASES = {"INTEGER": "INT64", "BOOLEAN": "BOOL", "STRUCT": "RECORD", "FLOAT": "FLOAT64"}


# ------------------------------------------------------------------ files
def table_names():
    return list(TABLES)


def resolve_table(name):
    """Accept the short name (security_events) or the BigQuery table name."""
    if name in TABLES:
        return name
    for short, spec in TABLES.items():
        if name in (spec[3], f"{spec[1]}.{spec[3]}"):
            return short
    raise SystemExit(f"Unknown table '{name}'. Choose from: {', '.join(TABLES)}")


def destination(short):
    ds_env, ds_default, tb_env, tb_default = TABLES[short][:4]
    return os.environ.get(ds_env, ds_default), os.environ.get(tb_env, tb_default)


def load_schema(short):
    with open(os.path.join(SCHEMA_DIR, short + ".json")) as fh:
        return json.load(fh)


def load_rows(short):
    rows = []
    with open(os.path.join(HERE, short + ".jsonl")) as fh:
        for n, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"{short}.jsonl line {n}: invalid JSON: {exc}") from exc
    return rows


# ------------------------------------------------------------------ validation
def parse_ts(value):
    if not isinstance(value, str) or not TS_RE.match(value):
        raise ValueError(f"not an ISO-8601 timestamp: {value!r}")
    v = value.replace(" ", "T")
    if v.endswith("Z"):
        v = v[:-1] + "+00:00"
    t = dt.datetime.fromisoformat(v)
    if t.tzinfo is None:
        t = t.replace(tzinfo=dt.timezone.utc)
    return t.astimezone(dt.timezone.utc)


def format_ts(t):
    t = t.astimezone(dt.timezone.utc)
    if t.microsecond:
        return t.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def _check_scalar(typ, value, path):
    if typ == "STRING":
        ok = isinstance(value, str)
    elif typ == "INT64":
        ok = isinstance(value, int) and not isinstance(value, bool)
    elif typ == "FLOAT64":
        ok = isinstance(value, (int, float)) and not isinstance(value, bool)
    elif typ == "BOOL":
        ok = isinstance(value, bool)
    elif typ == "TIMESTAMP":
        try:
            parse_ts(value)
            ok = True
        except ValueError:
            ok = False
    else:
        return [f"{path}: unsupported type {typ}"]
    return [] if ok else [f"{path}: expected {typ}, got {value!r}"]


def validate_row(row, schema, path="row"):
    """Return a list of error strings (empty if the row is valid)."""
    errors = []
    if not isinstance(row, dict):
        return [f"{path}: expected object, got {type(row).__name__}"]
    known = {f["name"] for f in schema}
    for key in row:
        if key not in known:
            errors.append(f"{path}.{key}: field not in schema")
    for field in schema:
        name = field["name"]
        typ = TYPE_ALIASES.get(field["type"].upper(), field["type"].upper())
        mode = field.get("mode", "NULLABLE").upper()
        fpath = f"{path}.{name}"
        value = row.get(name)
        if value is None:
            if mode == "REQUIRED":
                errors.append(f"{fpath}: REQUIRED field missing or null")
            continue
        items = value if mode == "REPEATED" else [value]
        if mode == "REPEATED" and not isinstance(value, list):
            errors.append(f"{fpath}: REPEATED field must be a list")
            continue
        for i, item in enumerate(items):
            ipath = f"{fpath}[{i}]" if mode == "REPEATED" else fpath
            if item is None and mode == "REPEATED":
                errors.append(f"{ipath}: null element in REPEATED field")
            elif typ == "RECORD":
                errors.extend(validate_row(item, field.get("fields", []), ipath))
            else:
                errors.extend(_check_scalar(typ, item, ipath))
    return errors


def validate_table(short, rows=None, schema=None):
    schema = schema if schema is not None else load_schema(short)
    rows = rows if rows is not None else load_rows(short)
    errors = []
    for n, row in enumerate(rows, 1):
        errors.extend(validate_row(row, schema, f"{short}[{n}]"))
    return errors


# ------------------------------------------------------------------ timestamp shift
def _walk_ts(row, schema):
    """Yield every TIMESTAMP value in a row (following nested/repeated records)."""
    for field in schema:
        value = row.get(field["name"]) if isinstance(row, dict) else None
        if value is None:
            continue
        typ = TYPE_ALIASES.get(field["type"].upper(), field["type"].upper())
        items = value if field.get("mode", "").upper() == "REPEATED" else [value]
        for item in items:
            if typ == "TIMESTAMP":
                yield parse_ts(item)
            elif typ == "RECORD":
                yield from _walk_ts(item, field.get("fields", []))


def newest_timestamp(tables):
    """tables: dict short -> (schema, rows). Returns the max TIMESTAMP across all tables."""
    newest = None
    for schema, rows in tables.values():
        for row in rows:
            for t in _walk_ts(row, schema):
                if newest is None or t > newest:
                    newest = t
    return newest


def compute_offset(tables, now=None):
    now = now or dt.datetime.now(dt.timezone.utc)
    newest = newest_timestamp(tables)
    if newest is None:
        return dt.timedelta(0)
    return dt.timedelta(seconds=int((now - newest).total_seconds()))


def _shift_json_value(obj, offset):
    if isinstance(obj, dict):
        return {k: _shift_json_value(v, offset) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_shift_json_value(v, offset) for v in obj]
    if isinstance(obj, str) and TS_RE.match(obj):
        return format_ts(parse_ts(obj) + offset)
    return obj


def _shift_json_text(text, offset):
    try:
        obj = json.loads(text)
    except (TypeError, ValueError):
        return text
    if not isinstance(obj, (dict, list)):
        return text
    return json.dumps(_shift_json_value(obj, offset), separators=(",", ":"))


def shift_row(row, schema, offset):
    out = copy.deepcopy(row)
    for field in schema:
        name = field["name"]
        value = out.get(name)
        if value is None:
            continue
        typ = TYPE_ALIASES.get(field["type"].upper(), field["type"].upper())
        repeated = field.get("mode", "").upper() == "REPEATED"
        items = value if repeated else [value]
        new = []
        for item in items:
            if typ == "TIMESTAMP":
                new.append(format_ts(parse_ts(item) + offset))
            elif typ == "RECORD":
                new.append(shift_row(item, field.get("fields", []), offset))
            elif typ == "STRING" and name in JSON_TEXT_FIELDS:
                new.append(_shift_json_text(item, offset))
            else:
                new.append(item)
        out[name] = new if repeated else new[0]
    return out


def substitute_project(obj, project):
    """Replace the your-gcp-project-id placeholder in every string value."""
    if project in (None, PROJECT_PLACEHOLDER):
        return obj
    if isinstance(obj, dict):
        return {k: substitute_project(v, project) for k, v in obj.items()}
    if isinstance(obj, list):
        return [substitute_project(v, project) for v in obj]
    if isinstance(obj, str):
        return obj.replace(PROJECT_PLACEHOLDER, project)
    return obj


def prepare(selected, shift=True, project=None, now=None):
    """Load, validate and transform rows. Offset is computed across ALL tables so the
    same event keeps the same time in every table even with --only."""
    all_tables = {s: (load_schema(s), load_rows(s)) for s in TABLES}
    errors = []
    for short, (schema, rows) in all_tables.items():
        errors.extend(validate_table(short, rows, schema))
    offset = compute_offset(all_tables, now) if shift else dt.timedelta(0)
    prepared = {}
    for short in selected:
        schema, rows = all_tables[short]
        rows = [shift_row(r, schema, offset) for r in rows] if shift else rows
        prepared[short] = (schema, substitute_project(rows, project))
    return prepared, offset, errors


# ------------------------------------------------------------------ BigQuery
def to_bq_schema(bigquery, fields):
    out = []
    for f in fields:
        sub = to_bq_schema(bigquery, f["fields"]) if f.get("fields") else ()
        out.append(bigquery.SchemaField(f["name"], f["type"], mode=f.get("mode", "NULLABLE"),
                                        fields=sub))
    return out


def load_to_bigquery(project, prepared, replace, location):
    try:
        from google.cloud import bigquery  # imported lazily: not needed for --dry-run
        from google.api_core.exceptions import NotFound
    except ImportError:
        raise SystemExit("google-cloud-bigquery is not installed. Run "
                         "`pip install google-cloud-bigquery`, or use load_seed_data.sh "
                         "(bq CLI), or --dry-run.")
    client = bigquery.Client(project=project)
    for short, (schema, rows) in prepared.items():
        dataset, table = destination(short)
        partition, clustering, sink_table = TABLES[short][4:7]
        ds_ref = bigquery.DatasetReference(project, dataset)
        try:
            client.get_dataset(ds_ref)
        except NotFound:
            print(f"  creating dataset {project}.{dataset} ({location})")
            ds = bigquery.Dataset(ds_ref)
            ds.location = location
            client.create_dataset(ds)
        table_id = f"{project}.{dataset}.{table}"
        exists = True
        try:
            client.get_table(table_id)
        except NotFound:
            exists = False
        if not exists:
            why = "normally created by the log sink" if sink_table else "missing"
            print(f"  creating table {table_id} from schemas/{short}.json ({why})")
            t = bigquery.Table(table_id, schema=to_bq_schema(bigquery, schema))
            if partition:
                t.time_partitioning = bigquery.TimePartitioning(
                    type_=bigquery.TimePartitioningType.DAY, field=partition)
            if clustering:
                t.clustering_fields = clustering
            client.create_table(t)
        job_config = bigquery.LoadJobConfig(
            source_format=bigquery.SourceFormat.NEWLINE_DELIMITED_JSON,
            write_disposition=(bigquery.WriteDisposition.WRITE_TRUNCATE if replace
                               else bigquery.WriteDisposition.WRITE_APPEND))
        # Existing tables keep their own schema (sink / SCC export tables have more columns).
        job = client.load_table_from_json(rows, table_id, job_config=job_config)
        job.result()
        print(f"  loaded {len(rows)} rows into {table_id}")


# ------------------------------------------------------------------ CLI
def build_parser():
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--project", default=os.environ.get("GCP_PROJECT_ID", PROJECT_PLACEHOLDER),
                   help="GCP project id (default: $GCP_PROJECT_ID)")
    p.add_argument("--location", default=os.environ.get("BQ_LOCATION", "US"),
                   help="Location for datasets created by this script (default US)")
    p.add_argument("--shift-to-now", dest="shift", action="store_true", default=True,
                   help="Shift all timestamps so the newest row is now (default)")
    p.add_argument("--no-shift", dest="shift", action="store_false",
                   help="Load the fixed 2026-10 timestamps as they are")
    p.add_argument("--replace", action="store_true",
                   help="Truncate each target table before loading (WRITE_TRUNCATE)")
    p.add_argument("--only", action="append", metavar="TABLE",
                   help="Load only this table (repeatable). Short name or BigQuery table name.")
    p.add_argument("--dry-run", action="store_true",
                   help="Validate rows and print planned actions; no GCP calls")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    selected = [resolve_table(t) for t in args.only] if args.only else table_names()
    prepared, offset, errors = prepare(selected, shift=args.shift, project=args.project)
    if errors:
        print(f"Schema validation FAILED ({len(errors)} errors):", file=sys.stderr)
        for e in errors:
            print("  " + e, file=sys.stderr)
        return 1
    print(f"Schema validation OK for {len(TABLES)} tables.")
    if args.shift:
        print(f"Timestamp shift: +{offset} (newest row becomes now).")
    else:
        print("Timestamp shift: disabled (--no-shift).")
    mode = "WRITE_TRUNCATE (--replace)" if args.replace else "WRITE_APPEND"
    for short, (_, rows) in prepared.items():
        dataset, table = destination(short)
        sink = " [sink table; created from schema only if missing]" if TABLES[short][6] else ""
        print(f"{'[dry-run] would load' if args.dry_run else 'load'} {len(rows):3d} rows "
              f"{short}.jsonl -> {args.project}.{dataset}.{table} ({mode}){sink}")
    if args.dry_run:
        print("Dry run complete. No changes made.")
        return 0
    load_to_bigquery(args.project, prepared, args.replace, args.location)
    print("Done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
