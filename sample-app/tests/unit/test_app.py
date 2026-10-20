"""Unit tests for legitimate behavior of payment-service.

These pass on the vulnerable code and on correctly patched code.
"""

import importlib.util
import unittest

from tests import SeededDbMixin
from app import db, receipts

HAS_FLASK = importlib.util.find_spec("flask") is not None


class TransactionsTest(SeededDbMixin, unittest.TestCase):
    def test_account_lookup_returns_only_its_rows(self):
        rows = db.get_transactions("ACC-1001")
        self.assertEqual(len(rows), 3)
        self.assertEqual({row["account"] for row in rows}, {"ACC-1001"})

    def test_other_accounts(self):
        self.assertEqual(len(db.get_transactions("ACC-1002")), 2)
        self.assertEqual(len(db.get_transactions("ACC-1003")), 2)

    def test_unknown_account_returns_no_rows(self):
        self.assertEqual(db.get_transactions("ACC-9999"), [])

    def test_init_db_is_idempotent(self):
        db.init_db()
        self.assertEqual(len(db.get_transactions("ACC-1001")), 3)


class ReceiptsTest(unittest.TestCase):
    def test_read_existing_receipt(self):
        text = receipts.read_receipt("receipt-0001.txt")
        self.assertIn("RECEIPT receipt-0001", text)
        self.assertIn("ACC-1001", text)

    def test_missing_receipt_raises(self):
        with self.assertRaises(receipts.ReceiptNotFound):
            receipts.read_receipt("receipt-9999.txt")


@unittest.skipUnless(HAS_FLASK, "flask not installed")
class FlaskRoutesTest(SeededDbMixin, unittest.TestCase):
    def setUp(self):
        super().setUp()
        from app.main import create_app

        self.client = create_app({"TESTING": True}).test_client()

    def test_health(self):
        resp = self.client.get("/health")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["status"], "ok")

    def test_transactions_route(self):
        resp = self.client.get("/api/transactions?account=ACC-1002")
        self.assertEqual(resp.status_code, 200)
        rows = resp.get_json()["transactions"]
        self.assertEqual({row["account"] for row in rows}, {"ACC-1002"})

    def test_transactions_requires_account(self):
        self.assertEqual(self.client.get("/api/transactions").status_code, 400)

    def test_receipt_route(self):
        resp = self.client.get("/api/receipts?file=receipt-0001.txt")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("RECEIPT receipt-0001", resp.get_data(as_text=True))

    def test_missing_receipt_is_404(self):
        resp = self.client.get("/api/receipts?file=receipt-9999.txt")
        self.assertEqual(resp.status_code, 404)


if __name__ == "__main__":
    unittest.main()
