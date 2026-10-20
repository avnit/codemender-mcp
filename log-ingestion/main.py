"""security-log-ingestion: Pub/Sub push endpoint that writes Cloud Logging entries to BigQuery.

Routes:
  GET  /health        liveness check
  POST /pubsub/push   Pub/Sub push envelope -> LogEntry -> BigQuery rows

Response policy:
  204  written, duplicate, or unparseable (unparseable is recorded in ingestion_errors)
  401  missing or invalid OIDC token (only when PUSH_AUDIENCE is set)
  403  token email does not match PUSH_SERVICE_ACCOUNT (only when that is set)
  500  transient BigQuery failure; Pub/Sub retries, then dead-letters to security-logs-dlq

Authentication: the service is deployed with --no-allow-unauthenticated, so
Cloud Run IAM already requires a valid token from an identity with
roles/run.invoker. Setting PUSH_AUDIENCE adds an in-app check of the push
token (google.oauth2.id_token.verify_oauth2_token). When PUSH_AUDIENCE is
unset the in-app check is skipped.
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import sys
from typing import Any, Callable, Dict, Optional, Tuple

from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from bq_writer import BigQueryWriter, PermanentWriteError, TransientWriteError
from config import SERVICE_NAME, Settings
from parser import ParseError, parse_log_entry, utc_now

logger = logging.getLogger(SERVICE_NAME)

TokenVerifier = Callable[[str, str], Dict[str, Any]]


class AuthError(Exception):
    def __init__(self, status: int, reason: str) -> None:
        super().__init__(reason)
        self.status = status
        self.reason = reason


def google_token_verifier() -> TokenVerifier:
    """Default verifier: checks signature, expiry, issuer and audience with Google's certs."""
    from google.auth.transport import requests as google_requests
    from google.oauth2 import id_token

    request = google_requests.Request()

    def verify(token: str, audience: str) -> Dict[str, Any]:
        return id_token.verify_oauth2_token(token, request, audience=audience)

    return verify


def decode_push_envelope(body: bytes) -> Tuple[Optional[str], Dict[str, Any], str]:
    """Return (message_id, log_entry, decoded_data_text). Raises ParseError."""
    try:
        envelope = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ParseError(f"request body is not JSON: {exc}") from exc
    if not isinstance(envelope, dict) or not isinstance(envelope.get("message"), dict):
        raise ParseError("request body is not a Pub/Sub push envelope (missing 'message')")
    message = envelope["message"]
    message_id = message.get("messageId") or message.get("message_id")
    message_id = str(message_id) if message_id is not None else None
    data = message.get("data")
    if not isinstance(data, str) or not data:
        raise ParseError("Pub/Sub message has no data")
    try:
        padded = data + "=" * (-len(data) % 4)
        if "-" in data or "_" in data:
            raw = base64.urlsafe_b64decode(padded)
        else:
            raw = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ParseError(f"message.data is not valid base64: {exc}") from exc
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ParseError("message.data is not UTF-8") from exc
    try:
        entry = json.loads(text)
    except ValueError as exc:
        raise _ParseErrorWithText(f"message.data is not JSON: {exc}", text) from exc
    if not isinstance(entry, dict):
        raise _ParseErrorWithText("message.data is not a JSON object", text)
    return message_id, entry, text


class _ParseErrorWithText(ParseError):
    def __init__(self, message: str, text: str) -> None:
        super().__init__(message)
        self.text = text


def _message_id_from_body(body: bytes) -> Optional[str]:
    try:
        message = json.loads(body.decode("utf-8")).get("message", {})
        value = message.get("messageId") or message.get("message_id")
        return str(value) if value is not None else None
    except Exception:  # noqa: BLE001
        return None


def create_app(
    settings: Optional[Settings] = None,
    writer: Optional[BigQueryWriter] = None,
    token_verifier: Optional[TokenVerifier] = None,
) -> Starlette:
    settings = settings or Settings.from_env()
    writer = writer or BigQueryWriter(settings)
    verifier_holder: Dict[str, Optional[TokenVerifier]] = {"fn": token_verifier}

    def get_verifier() -> TokenVerifier:
        if verifier_holder["fn"] is None:
            verifier_holder["fn"] = google_token_verifier()
        return verifier_holder["fn"]

    async def check_auth(request: Request) -> None:
        if not settings.push_audience:
            return
        header = request.headers.get("authorization", "")
        scheme, _, token = header.partition(" ")
        if scheme.lower() != "bearer" or not token.strip():
            raise AuthError(401, "missing bearer token")
        try:
            claims = await run_in_threadpool(get_verifier(), token.strip(), settings.push_audience)
        except Exception as exc:  # noqa: BLE001 - any verification failure is a 401
            raise AuthError(401, f"invalid token: {type(exc).__name__}") from exc
        if settings.push_service_account:
            if claims.get("email") != settings.push_service_account or not claims.get("email_verified"):
                raise AuthError(403, "token email does not match PUSH_SERVICE_ACCOUNT")

    async def record_error(
        error: str,
        raw: Any,
        message_id: Optional[str],
        insert_id: Optional[str],
        received_at: str,
    ) -> Response:
        log(logging.WARNING, "message not ingested; recording in ingestion_errors", error=error, message_id=message_id, insert_id=insert_id)
        try:
            await run_in_threadpool(
                writer.write_ingestion_error,
                error,
                raw,
                message_id,
                insert_id,
                received_at,
            )
        except TransientWriteError as exc:
            log(logging.ERROR, "ingestion_errors write failed; asking Pub/Sub to retry", error=str(exc))
            return Response(status_code=500)
        except PermanentWriteError as exc:
            log(logging.ERROR, "ingestion_errors write rejected; dropping message", error=str(exc))
        return Response(status_code=204)

    async def health(request: Request) -> Response:
        return JSONResponse({"status": "ok", "service": SERVICE_NAME})

    async def pubsub_push(request: Request) -> Response:
        try:
            await check_auth(request)
        except AuthError as exc:
            log(logging.WARNING, "push auth failed", reason=exc.reason)
            return JSONResponse({"error": exc.reason}, status_code=exc.status)

        received_at = utc_now()
        body = await request.body()

        try:
            message_id, entry, text = decode_push_envelope(body)
        except ParseError as exc:
            raw = getattr(exc, "text", None) or body
            return await record_error(str(exc), raw, _message_id_from_body(body), None, received_at)

        try:
            parsed = parse_log_entry(entry, ingest_timestamp=received_at)
        except ParseError as exc:
            insert_id = entry.get("insertId")
            return await record_error(
                str(exc), text, message_id, str(insert_id) if insert_id is not None else None, received_at
            )

        try:
            result = await run_in_threadpool(writer.write_parsed, parsed)
        except TransientWriteError as exc:
            log(logging.ERROR, "transient BigQuery error", error=str(exc), insert_id=parsed.insert_id)
            return Response(status_code=500)
        except PermanentWriteError as exc:
            return await record_error(str(exc), text, message_id, parsed.insert_id, received_at)

        log(
            logging.INFO,
            "duplicate skipped" if result == "duplicate" else "event written",
            insert_id=parsed.insert_id,
            event_type=parsed.event_type,
            message_id=message_id,
        )
        return Response(status_code=204)

    app = Starlette(
        routes=[
            Route("/health", health, methods=["GET"]),
            Route("/pubsub/push", pubsub_push, methods=["POST"]),
        ]
    )
    app.state.settings = settings
    app.state.writer = writer
    return app


def log(level: int, message: str, **fields: Any) -> None:
    """One JSON line per event; Cloud Run turns it into a structured LogEntry."""
    severity = logging.getLevelName(level)
    payload = {"severity": severity, "message": message, "service": SERVICE_NAME}
    payload.update({k: v for k, v in fields.items() if v is not None})
    logger.log(level, json.dumps(payload, default=str))


def _configure_logging() -> None:
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False


_configure_logging()
app = create_app()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=Settings.from_env().port)
