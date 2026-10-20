# =====================================================================
# INTENTIONALLY VULNERABLE IMAGE - LAB / SANDBOX USE ONLY.
# CM-0004 / CWE-1104: python:3.8-slim-buster is an end-of-life base
# image (Python 3.8 and Debian 10 "buster" no longer get security fixes).
# Expected fix: move to a supported base, e.g. python:3.12-slim-bookworm.
# =====================================================================
FROM python:3.8-slim-buster

LABEL org.opencontainers.image.source="https://github.com/your-github-org/payment-service"
LABEL org.opencontainers.image.description="payment-service: intentionally vulnerable lab app. Do not deploy to production."

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /srv/payment-service

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ app/
COPY data/ data/

RUN useradd --create-home --uid 10001 appuser \
    && chown -R appuser:appuser /srv/payment-service/data
USER appuser

# The app binds to 127.0.0.1 unless HOST is set. A container must listen on
# 0.0.0.0 to be reachable (Cloud Run sends traffic to PORT, default 8080).
ENV HOST=0.0.0.0 \
    PORT=8080
EXPOSE 8080

CMD ["python", "-m", "app.main"]
