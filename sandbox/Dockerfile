# CodeMender sandbox runner image (Cloud Run Job `codemender-sandbox`).
#
# The job has no internet egress at runtime (Direct VPC egress ALL_TRAFFIC to
# sandbox-vpc, deny-all egress firewall). pip cannot run inside the job, so
# every dependency the PoC and unit tests need is baked in at build time.
# If the code under test needs more packages, add them to requirements.txt
# and rebuild.
#
# Base image is pinned to a patch version. For stricter pinning, replace the
# tag with a digest: python:3.12.7-slim-bookworm@sha256:<digest>
FROM python:3.12.7-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# git (for `git apply`) and patch (fallback). Nothing else.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git patch \
    && rm -rf /var/lib/apt/lists/*

# Dependencies are baked in at build time: pytest for PoC/unit tests, Flask
# for the sample app (payment-service), google-auth + requests for reading
# inputs from GCS.
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY runner/ /app/runner/

# Non-root user. Source is extracted under /tmp (in-memory on Cloud Run).
RUN useradd --uid 10001 --create-home --home-dir /home/sandbox --shell /usr/sbin/nologin sandbox \
    && chmod -R a-w /app
USER 10001:10001
WORKDIR /tmp
ENV HOME=/home/sandbox

ENTRYPOINT ["python", "/app/runner/runner.py"]
