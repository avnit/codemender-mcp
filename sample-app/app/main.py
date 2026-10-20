# =====================================================================
# INTENTIONALLY VULNERABLE CODE - LAB / SANDBOX USE ONLY.
# Routes expose CM-0001 (SQL injection) and CM-0002 (path traversal).
# Binds to 127.0.0.1 by default; set HOST to override.
# =====================================================================
"""Flask app factory for payment-service."""

import logging
import os

from flask import Flask, Response, jsonify, request

from app import db, receipts

logger = logging.getLogger("payment-service")

WARNING_LINE = (
    "payment-service is INTENTIONALLY VULNERABLE (CM-0001 SQLi, CM-0002 path "
    "traversal). Lab/sandbox use only. Do not expose to untrusted networks."
)


def create_app(config=None):
    """Build the Flask app and initialize the local SQLite database."""
    app = Flask(__name__)
    app.config["DB_PATH"] = None
    if config:
        app.config.update(config)

    logging.basicConfig(level=logging.INFO)
    logger.warning(WARNING_LINE)
    db.init_db(app.config["DB_PATH"])

    @app.get("/health")
    def health():
        return jsonify({"status": "ok", "service": "payment-service"})

    @app.get("/api/transactions")
    def transactions():
        account = request.args.get("account")
        if not account:
            return jsonify({"error": "missing 'account' query parameter"}), 400
        rows = db.get_transactions(account, app.config["DB_PATH"])
        return jsonify({"account": account, "transactions": rows})

    @app.get("/api/receipts")
    def get_receipt():
        name = request.args.get("file")
        if not name:
            return jsonify({"error": "missing 'file' query parameter"}), 400
        try:
            text = receipts.read_receipt(name)
        except receipts.ReceiptNotFound:
            return jsonify({"error": "receipt not found"}), 404
        return Response(text, mimetype="text/plain")

    return app


def main():
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8080"))
    create_app().run(host=host, port=port)


if __name__ == "__main__":
    main()
