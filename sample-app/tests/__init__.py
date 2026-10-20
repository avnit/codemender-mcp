"""Tests for payment-service (lab app). Run from sample-app/:

    PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v

Tests use one SQLite file, data/test_payments.db (gitignored), re-seeded by
init_db() before each test. Override its location with TEST_DB_PATH.
"""

import os
import sys

APP_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if APP_ROOT not in sys.path:
    sys.path.insert(0, APP_ROOT)


def test_db_path():
    return os.environ.get("TEST_DB_PATH") or os.path.join(APP_ROOT, "data", "test_payments.db")


class SeededDbMixin:
    """Point DB_PATH at the test database and re-seed it."""

    def setUp(self):
        from app import db

        self._old_db_path = os.environ.get("DB_PATH")
        os.environ["DB_PATH"] = test_db_path()
        db.init_db()

    def tearDown(self):
        if self._old_db_path is None:
            os.environ.pop("DB_PATH", None)
        else:
            os.environ["DB_PATH"] = self._old_db_path
