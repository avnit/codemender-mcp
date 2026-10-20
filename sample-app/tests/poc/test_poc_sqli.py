"""PoC for CM-0001 (CWE-89 SQL injection in app/db.py:get_transactions).

PASSES while the injection works; FAILS once the query is parameterized.
Local SQLite file built from seed rows only.
"""

import importlib.util
import unittest

from tests import SeededDbMixin
from app import db

HAS_FLASK = importlib.util.find_spec("flask") is not None
PAYLOAD = "' OR '1'='1"


class SqliPocTest(SeededDbMixin, unittest.TestCase):
    def test_injection_returns_rows_for_other_accounts(self):
        rows = db.get_transactions(PAYLOAD)
        accounts = {row["account"] for row in rows}
        self.assertGreater(
            len(accounts), 1,
            "exploit blocked: injected account filter did not return other accounts' rows",
        )


@unittest.skipUnless(HAS_FLASK, "flask not installed")
class SqliPocFlaskTest(SeededDbMixin, unittest.TestCase):
    def test_injection_via_http_route(self):
        from app.main import create_app

        client = create_app({"TESTING": True}).test_client()
        resp = client.get("/api/transactions", query_string={"account": PAYLOAD})
        self.assertEqual(resp.status_code, 200)
        accounts = {row["account"] for row in resp.get_json()["transactions"]}
        self.assertGreater(len(accounts), 1, "exploit blocked via HTTP route")


if __name__ == "__main__":
    unittest.main()
