# =====================================================================
# INTENTIONALLY VULNERABLE CODE - LAB / SANDBOX USE ONLY.
# CM-0002 / CWE-22: read_receipt() joins user input to the receipts
# directory without normalizing or checking the result.
# Reference fix: patches/CM-0002-path-traversal.diff
# =====================================================================
"""Receipt file access for payment-service."""

import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RECEIPTS_DIR = os.path.join(BASE_DIR, "data", "receipts")


class ReceiptNotFound(Exception):
    """Raised when a receipt does not exist (or is not allowed)."""


def read_receipt(name, receipts_dir=None):
    """Return the text of a receipt file from the receipts directory."""
    base = receipts_dir or RECEIPTS_DIR
    # VULNERABLE (CWE-22): "../" sequences in name escape the receipts dir.
    path = os.path.join(base, name)
    if not os.path.isfile(path):
        raise ReceiptNotFound(name)
    with open(path, encoding="utf-8") as handle:
        return handle.read()
