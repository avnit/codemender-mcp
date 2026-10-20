# =====================================================================
# INTENTIONALLY VULNERABLE CODE - LAB / SANDBOX USE ONLY.
# CM-0001 / CWE-89: get_transactions() builds SQL with an f-string.
# Reference fix: patches/CM-0001-sqli.diff
# =====================================================================
"""SQLite access for payment-service."""

import os
import sqlite3

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_DB_PATH = os.path.join("data", "payments.db")

SEED_TRANSACTIONS = [
    ("ACC-1001", 1250, "USD", "Coffee Corner", "2026-01-05T09:15:00Z"),
    ("ACC-1001", 4999, "USD", "Book Barn", "2026-01-07T13:02:00Z"),
    ("ACC-1001", 15000, "USD", "Grocery Hub", "2026-01-09T18:40:00Z"),
    ("ACC-1002", 8900, "USD", "Fuel Stop", "2026-01-06T07:55:00Z"),
    ("ACC-1002", 2300, "USD", "Lunch Place", "2026-01-08T12:10:00Z"),
    ("ACC-1003", 120000, "USD", "Electronics Depot", "2026-01-04T16:20:00Z"),
    ("ACC-1003", 650, "USD", "Parking Meter", "2026-01-10T10:05:00Z"),
]


def get_db_path(db_path=None):
    """Return the SQLite file path. Relative paths resolve from the app root."""
    path = db_path or os.environ.get("DB_PATH", DEFAULT_DB_PATH)
    if not os.path.isabs(path):
        path = os.path.join(BASE_DIR, path)
    return path


def _connect(db_path=None):
    conn = sqlite3.connect(get_db_path(db_path))
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path=None):
    """Create the transactions table and (re)load the seed rows."""
    path = get_db_path(db_path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    conn = _connect(path)
    try:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS transactions ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "account TEXT NOT NULL, "
            "amount_cents INTEGER NOT NULL, "
            "currency TEXT NOT NULL, "
            "merchant TEXT NOT NULL, "
            "created_at TEXT NOT NULL)"
        )
        conn.execute("DELETE FROM transactions")
        conn.executemany(
            "INSERT INTO transactions (account, amount_cents, currency, merchant, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            SEED_TRANSACTIONS,
        )
        conn.commit()
    finally:
        conn.close()
    return path


def get_transactions(account, db_path=None):
    """Return the transactions for one account as a list of dicts."""
    conn = _connect(db_path)
    try:
        # VULNERABLE (CWE-89): user input is interpolated into the SQL text.
        query = (
            "SELECT id, account, amount_cents, currency, merchant, created_at "
            f"FROM transactions WHERE account = '{account}' ORDER BY id"
        )
        rows = conn.execute(query).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()
