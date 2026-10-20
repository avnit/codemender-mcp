# =====================================================================
# INTENTIONALLY VULNERABLE CODE - LAB / SANDBOX USE ONLY.
# payment-service is a training target for the AI security agent lab.
# Do not deploy to production or expose to untrusted networks.
# =====================================================================
"""payment-service: intentionally vulnerable Flask app for the security lab.

This package does not import Flask at import time, so app.db and
app.receipts can be imported and tested without Flask installed.
Use app.main.create_app() to build the Flask application.
"""

__all__ = ["db", "receipts"]
