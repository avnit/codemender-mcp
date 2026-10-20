"""PoC for CM-0002 (CWE-22 path traversal in app/receipts.py:read_receipt).

PASSES while "../" escapes the receipts directory; FAILS once the path is
resolved and checked. Reads only data/not_a_secret.txt (a dummy file).
"""

import importlib.util
import unittest

from tests import SeededDbMixin
from app import receipts

HAS_FLASK = importlib.util.find_spec("flask") is not None
PAYLOAD = "../not_a_secret.txt"
DUMMY = "THIS-IS-A-DUMMY-FILE-FOR-THE-PATH-TRAVERSAL-DEMO"


class PathTraversalPocTest(unittest.TestCase):
    def test_traversal_reads_dummy_file(self):
        try:
            text = receipts.read_receipt(PAYLOAD)
        except receipts.ReceiptNotFound:
            self.fail("exploit blocked: read_receipt rejected the traversal path")
        self.assertIn(DUMMY, text)


@unittest.skipUnless(HAS_FLASK, "flask not installed")
class PathTraversalPocFlaskTest(SeededDbMixin, unittest.TestCase):
    def test_traversal_via_http_route(self):
        from app.main import create_app

        client = create_app({"TESTING": True}).test_client()
        resp = client.get("/api/receipts", query_string={"file": PAYLOAD})
        self.assertEqual(resp.status_code, 200, "exploit blocked via HTTP route")
        self.assertIn(DUMMY, resp.get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()
