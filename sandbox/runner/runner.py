"""CodeMender sandbox runner.

Runs inside the Cloud Run Job `codemender-sandbox`. One execution validates
one patch against one commit:

  1. Validate inputs from environment variables.
  2. Download the source tarball and the patch (GCS or local file).
  3. Extract the tarball safely.
  4. Run the PoC test against the unpatched code (exit 0 = EXPLOITABLE).
  5. Apply the patch (`git apply`, or `patch -p1` if git is missing).
  6. Run the PoC test again.
  7. Run the unit tests.
  8. Compute the verdict and print ONE `SANDBOX_RESULT` JSON line to stdout.

Exit code is 0 for every completed run (any verdict except ERROR) and 1 for
ERROR. Progress messages go to stderr so stdout carries exactly one line.

Nothing is downloaded or executed from the network except the two input
objects read from GCS. No command is run through a shell.
"""

from __future__ import annotations

import datetime as _dt
import importlib.util
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.parse
import urllib.request
import uuid

COMPONENT = "codemender-sandbox"
EVENT_TYPE = "SANDBOX_RESULT"

# Field order follows NAMING.md.
RESULT_FIELDS = (
    "severity",
    "message",
    "event_type",
    "run_id",
    "execution_name",
    "repository",
    "commit_sha",
    "patch_ref",
    "issue_id",
    "poc_test",
    "started_at",
    "finished_at",
    "poc_before",
    "poc_after",
    "patch_applied",
    "unit_tests_passed",
    "tests_total",
    "tests_failed",
    "verdict",
    "log_excerpt",
    "logging.googleapis.com/labels",
)

EXPLOITABLE = "EXPLOITABLE"
NOT_EXPLOITABLE = "NOT_EXPLOITABLE"
POC_ERROR = "ERROR"

PATCH_VERIFIED = "PATCH_VERIFIED"
PATCH_FAILED = "PATCH_FAILED"
POC_NOT_REPRODUCED = "POC_NOT_REPRODUCED"
VERDICT_ERROR = "ERROR"

DEFAULT_POC_TEST = "tests/poc"
DEFAULT_UNIT_TEST_CMD = "python -m pytest -q tests/unit"
DEFAULT_POC_CMD = "python -m pytest -q {poc_test}"
DEFAULT_TIMEOUT_SECONDS = 600
MAX_TIMEOUT_SECONDS = 3600

LOG_EXCERPT_LIMIT = 4000
STEP_OUTPUT_LIMIT = 1500

MAX_SOURCE_BYTES = 200 * 1024 * 1024  # compressed tarball
MAX_EXTRACTED_BYTES = 1024 * 1024 * 1024
MAX_TAR_MEMBERS = 50_000
MAX_PATCH_BYTES = 5 * 1024 * 1024

GCS_READ_SCOPE = "https://www.googleapis.com/auth/devstorage.read_only"
GCS_DOWNLOAD_URL = "https://storage.googleapis.com/storage/v1/b/{bucket}/o/{obj}?alt=media"

RE_COMMIT = re.compile(r"^[0-9a-fA-F]{7,40}$")
RE_REPOSITORY = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}$")
RE_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
RE_REL_PATH = re.compile(r"^[A-Za-z0-9._/-]{1,512}$")
RE_BUCKET = re.compile(r"^[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]$")

# pytest summary, e.g. "1 failed, 3 passed in 0.12s" or "=== 4 passed in 0.1s ==="
RE_PYTEST_SUMMARY = re.compile(r"\d+ (?:passed|failed|errors?)\b.* in [\d.]+s")
RE_PYTEST_COUNT = re.compile(r"(\d+) (passed|failed|errors?|skipped|xfailed|xpassed)\b")
# unittest summary
RE_UNITTEST_RAN = re.compile(r"^Ran (\d+) tests? in ", re.MULTILINE)
RE_UNITTEST_FAILED = re.compile(r"^FAILED \(([^)]*)\)", re.MULTILINE)


class InputError(Exception):
    """Invalid or unsafe input. Leads to verdict ERROR."""


class InfraError(Exception):
    """Download, extraction or tooling failure. Leads to verdict ERROR."""


# --------------------------------------------------------------------------
# Logging helpers
# --------------------------------------------------------------------------


def utc_now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def log_progress(message: str, severity: str = "INFO") -> None:
    """Structured progress line on stderr (never stdout)."""
    line = {
        "severity": severity,
        "message": message,
        "logging.googleapis.com/labels": {"component": COMPONENT},
    }
    print(json.dumps(line), file=sys.stderr, flush=True)


class StepLog:
    """Collects step output for log_excerpt."""

    def __init__(self) -> None:
        self.parts: list[str] = []

    def add(self, text: str) -> None:
        self.parts.append(text.rstrip("\n"))

    def add_output(self, title: str, output: str) -> None:
        output = output or ""
        if len(output) > STEP_OUTPUT_LIMIT:
            output = "...[truncated]...\n" + output[-STEP_OUTPUT_LIMIT:]
        self.add(f"--- {title} ---\n{output}")

    def excerpt(self) -> str:
        return truncate("\n".join(self.parts), LOG_EXCERPT_LIMIT)


def truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    marker = "...[truncated]...\n"
    return marker + text[-(limit - len(marker)):]


# --------------------------------------------------------------------------
# Input validation
# --------------------------------------------------------------------------


def _clean(value: str | None, limit: int = 256) -> str | None:
    """Raw env value, shortened, for reporting even when invalid."""
    if value is None:
        return None
    return value[:limit]


def validate_commit(value: str) -> str:
    if not value or not RE_COMMIT.match(value):
        raise InputError("COMMIT_SHA must be 7-40 hex characters")
    return value.lower()


def validate_repository(value: str) -> str:
    if not value or not RE_REPOSITORY.match(value):
        raise InputError("REPOSITORY must look like owner/name")
    name = value.split("/", 1)[1]
    if name in (".", ".."):
        raise InputError("REPOSITORY name is invalid")
    return value


def validate_id(name: str, value: str, required: bool) -> str:
    if not value:
        if required:
            raise InputError(f"{name} is required")
        return ""
    if not RE_ID.match(value):
        raise InputError(f"{name} contains invalid characters")
    return value


def validate_relative_path(name: str, value: str) -> str:
    if not value or not RE_REL_PATH.match(value):
        raise InputError(f"{name} must be a relative path using [A-Za-z0-9._/-]")
    if value.startswith("/") or ".." in value.split("/"):
        raise InputError(f"{name} must not be absolute or contain '..'")
    return value


def validate_timeout(value: str | None) -> int:
    if value in (None, ""):
        return DEFAULT_TIMEOUT_SECONDS
    try:
        seconds = int(value)
    except ValueError as exc:
        raise InputError("TIMEOUT_SECONDS must be an integer") from exc
    if not 1 <= seconds <= MAX_TIMEOUT_SECONDS:
        raise InputError(f"TIMEOUT_SECONDS must be between 1 and {MAX_TIMEOUT_SECONDS}")
    return seconds


def parse_uri(name: str, uri: str) -> tuple[str, str, str]:
    """Return ("gs", bucket, object) or ("file", path, "").

    Only gs:// URIs, file:// URIs and plain local paths are accepted.
    """
    if not uri:
        raise InputError(f"{name} is required")
    if any(ch in uri for ch in ("\n", "\r", "\x00")):
        raise InputError(f"{name} contains control characters")
    if uri.startswith("gs://"):
        rest = uri[len("gs://"):]
        bucket, _, obj = rest.partition("/")
        if not RE_BUCKET.match(bucket) or ".." in bucket:
            raise InputError(f"{name} has an invalid bucket name")
        if not obj or obj.endswith("/") or ".." in obj.split("/") or len(obj) > 1024:
            raise InputError(f"{name} has an invalid object name")
        return "gs", bucket, obj
    if uri.startswith("file://"):
        parsed = urllib.parse.urlparse(uri)
        if parsed.netloc not in ("", "localhost"):
            raise InputError(f"{name} file:// URI must not name a host")
        path = urllib.parse.unquote(parsed.path)
        if not path:
            raise InputError(f"{name} file:// URI has no path")
        return "file", path, ""
    if "://" in uri or re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", uri):
        raise InputError(f"{name} must be a gs:// URI or a local file path")
    return "file", uri, ""


def build_command(template: str, poc_test: str | None = None) -> list[str]:
    """Split a command template without a shell.

    `{poc_test}` is replaced with the PoC path. If the template has no
    placeholder and poc_test is given, the path is appended. A leading
    `python` / `python3` is replaced with the runner's interpreter so the
    baked-in dependencies are used.
    """
    try:
        args = shlex.split(template)
    except ValueError as exc:
        raise InputError(f"cannot parse command: {exc}") from exc
    if not args:
        raise InputError("command is empty")
    if poc_test is not None:
        if any("{poc_test}" in a for a in args):
            args = [a.replace("{poc_test}", poc_test) for a in args]
        else:
            args.append(poc_test)
    if args[0] in ("python", "python3"):
        args[0] = sys.executable
    return args


def load_config(env: dict[str, str]) -> dict:
    """Validate the environment. Raises InputError."""
    cfg: dict = {}
    cfg["run_id"] = validate_id("RUN_ID", env.get("RUN_ID", ""), required=True)
    cfg["repository"] = validate_repository(env.get("REPOSITORY", ""))
    cfg["commit_sha"] = validate_commit(env.get("COMMIT_SHA", ""))
    cfg["issue_id"] = validate_id("ISSUE_ID", env.get("ISSUE_ID", ""), required=False)
    cfg["poc_test"] = validate_relative_path("POC_TEST", env.get("POC_TEST") or DEFAULT_POC_TEST)
    cfg["timeout"] = validate_timeout(env.get("TIMEOUT_SECONDS"))

    cfg["source_uri"] = env.get("SOURCE_URI", "")
    cfg["source"] = parse_uri("SOURCE_URI", cfg["source_uri"])

    patch_uri = env.get("PATCH_URI", "") or "none"
    cfg["patch_uri"] = patch_uri
    cfg["patch"] = None if patch_uri == "none" else parse_uri("PATCH_URI", patch_uri)

    cfg["poc_cmd"] = build_command(env.get("POC_CMD") or DEFAULT_POC_CMD, cfg["poc_test"])
    cfg["unit_cmd"] = build_command(env.get("UNIT_TEST_CMD") or DEFAULT_UNIT_TEST_CMD)
    return cfg


# --------------------------------------------------------------------------
# Input download
# --------------------------------------------------------------------------


def _gcs_token() -> str:
    """Access token from Application Default Credentials (the job's SA)."""
    import google.auth  # imported lazily; not needed for local runs

    try:
        from google.auth.transport.requests import Request as AuthRequest
    except ImportError:  # requests not installed
        from google.auth.transport._http_client import Request as AuthRequest

    credentials, _ = google.auth.default(scopes=[GCS_READ_SCOPE])
    credentials.refresh(AuthRequest())
    return credentials.token


def download_gcs(bucket: str, obj: str, dest: str, max_bytes: int, timeout: float) -> None:
    url = GCS_DOWNLOAD_URL.format(
        bucket=urllib.parse.quote(bucket, safe=""),
        obj=urllib.parse.quote(obj, safe=""),
    )
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {_gcs_token()}"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp, open(dest, "wb") as out:
            _copy_limited(resp, out, max_bytes)
    except urllib.error.HTTPError as exc:
        raise InfraError(f"GCS download failed: HTTP {exc.code} for gs://{bucket}/{obj}") from exc
    except urllib.error.URLError as exc:
        raise InfraError(f"GCS download failed: {exc.reason}") from exc


def _copy_limited(src, dst, max_bytes: int) -> None:
    total = 0
    while True:
        chunk = src.read(1024 * 1024)
        if not chunk:
            return
        total += len(chunk)
        if total > max_bytes:
            raise InfraError(f"input larger than {max_bytes} bytes")
        dst.write(chunk)


def fetch_input(parsed: tuple[str, str, str], dest: str, max_bytes: int, timeout: float) -> None:
    kind, a, b = parsed
    if kind == "gs":
        download_gcs(a, b, dest, max_bytes, timeout)
        return
    path = a
    if not os.path.isfile(path):
        raise InfraError(f"local input not found: {path}")
    if os.path.getsize(path) > max_bytes:
        raise InfraError(f"input larger than {max_bytes} bytes")
    with open(path, "rb") as src, open(dest, "wb") as out:
        _copy_limited(src, out, max_bytes)


# --------------------------------------------------------------------------
# Safe extraction
# --------------------------------------------------------------------------


def _is_within(base: str, target: str) -> bool:
    base = os.path.realpath(base)
    target = os.path.realpath(target)
    return target == base or target.startswith(base + os.sep)


def check_tar_members(members: list[tarfile.TarInfo], dest: str) -> list[tarfile.TarInfo]:
    """Reject unsafe members. Returns members to extract (skips .git/)."""
    if len(members) > MAX_TAR_MEMBERS:
        raise InputError(f"tarball has more than {MAX_TAR_MEMBERS} entries")
    total = 0
    keep = []
    for m in members:
        name = m.name
        if not name or name.startswith("/") or name.startswith("\\") or re.match(r"^[A-Za-z]:", name):
            raise InputError(f"tarball entry has absolute path: {name!r}")
        parts = [p for p in name.replace("\\", "/").split("/") if p not in ("", ".")]
        if ".." in parts:
            raise InputError(f"tarball entry contains '..': {name!r}")
        if not parts:
            continue
        if ".git" in parts:
            # A shipped .git directory could carry hooks or config; drop it.
            continue
        if m.isdev() or m.isfifo():
            raise InputError(f"tarball entry is a device or fifo: {name!r}")
        if m.issym() or m.islnk():
            link = m.linkname
            if not link or link.startswith("/"):
                raise InputError(f"tarball link has absolute target: {name!r} -> {link!r}")
            if m.issym():
                target = os.path.join(dest, os.path.dirname(name), link)
            else:
                target = os.path.join(dest, link)
            if not _is_within(dest, target):
                raise InputError(f"tarball link escapes the source dir: {name!r} -> {link!r}")
        if not (m.isfile() or m.isdir() or m.issym() or m.islnk()):
            raise InputError(f"tarball entry has unsupported type: {name!r}")
        total += max(m.size, 0)
        if total > MAX_EXTRACTED_BYTES:
            raise InputError("tarball expands beyond the size limit")
        keep.append(m)
    return keep


def safe_extract(tar_path: str, dest: str) -> str:
    """Extract tar_path into dest. Returns the source root directory."""
    try:
        with tarfile.open(tar_path, "r:*") as tar:
            members = check_tar_members(tar.getmembers(), dest)
            if hasattr(tarfile, "data_filter"):
                tar.extractall(dest, members=members, filter="data")
            else:  # pragma: no cover - Python < 3.12
                tar.extractall(dest, members=members)
    except tarfile.TarError as exc:
        raise InputError(f"cannot read tarball: {exc}") from exc

    # Second pass: no extracted symlink may point outside dest.
    for root, dirs, files in os.walk(dest):
        for entry in dirs + files:
            full = os.path.join(root, entry)
            if os.path.islink(full) and not _is_within(dest, full):
                raise InputError(f"extracted symlink escapes the source dir: {entry}")

    # Tarballs with a single top-level directory (e.g. GitHub archives).
    entries = [e for e in os.listdir(dest) if e not in (".", "..")]
    if len(entries) == 1:
        only = os.path.join(dest, entries[0])
        if os.path.isdir(only) and not os.path.islink(only):
            return only
    return dest


# --------------------------------------------------------------------------
# Patch handling
# --------------------------------------------------------------------------


def _patch_path(raw: str) -> str | None:
    path = raw.split("\t", 1)[0].strip()
    if path.startswith('"') and path.endswith('"'):
        path = path[1:-1]
    if path == "/dev/null":
        return None
    return path


def check_patch_paths(patch_text: str) -> list[str]:
    """Reject patches that touch paths outside the source tree or add symlinks."""
    touched = []
    for line in patch_text.splitlines():
        candidates = []
        if line.startswith("--- ") or line.startswith("+++ "):
            candidates.append(_patch_path(line[4:]))
        elif line.startswith("diff --git "):
            candidates.extend(line[len("diff --git "):].split(" "))
        elif line.startswith(("rename from ", "rename to ", "copy from ", "copy to ")):
            candidates.append(line.split(" ", 2)[2])
        elif re.match(r"^(new file mode|new mode|old mode|deleted file mode) 120000", line):
            raise InputError("patch creates or changes a symlink")
        for path in candidates:
            if path is None:
                continue
            if path.startswith("/"):
                raise InputError(f"patch touches an absolute path: {path!r}")
            if ".." in path.split("/"):
                raise InputError(f"patch path contains '..': {path!r}")
            touched.append(path)
    if not touched:
        raise InputError("patch contains no file headers")
    return touched


def apply_patch(src_dir: str, patch_file: str, env: dict, deadline: float, log: StepLog) -> bool:
    """Apply patch. Returns True on success, False if it does not apply."""
    git = shutil.which("git")
    if git:
        check = [git, "apply", "--check", "--whitespace=nowarn", patch_file]
        apply = [git, "apply", "--whitespace=nowarn", patch_file]
        tool = "git apply"
    else:
        tool_path = shutil.which("patch")
        if not tool_path:
            raise InfraError("neither git nor patch is installed")
        check = [tool_path, "-p1", "-N", "-t", "--dry-run", "-i", patch_file]
        apply = [tool_path, "-p1", "-N", "-t", "-i", patch_file]
        tool = "patch -p1"

    rc, out, timed_out = run_limited(check, src_dir, env, remaining(deadline))
    log.add_output(f"{tool} --check (exit {rc})", out)
    if timed_out:
        raise InfraError("patch check timed out")
    if rc != 0:
        return False
    rc, out, timed_out = run_limited(apply, src_dir, env, remaining(deadline))
    log.add_output(f"{tool} (exit {rc})", out)
    if timed_out:
        raise InfraError("patch apply timed out")
    return rc == 0


# --------------------------------------------------------------------------
# Subprocess execution
# --------------------------------------------------------------------------


def remaining(deadline: float) -> float:
    return max(deadline - time.monotonic(), 0.0)


def child_env(work_root: str, src_dir: str) -> dict:
    """Minimal environment for test processes. No inputs, no credentials."""
    home = os.path.join(work_root, "home")
    os.makedirs(home, exist_ok=True)
    return {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "HOME": home,
        "TMPDIR": os.path.join(work_root, "tmp"),
        "LANG": "C.UTF-8",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONUNBUFFERED": "1",
        "PYTHONHASHSEED": "0",
        "GIT_CEILING_DIRECTORIES": os.path.dirname(os.path.realpath(src_dir)),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
    }


def run_limited(args: list[str], cwd: str, env: dict, timeout: float) -> tuple[int, str, bool]:
    """Run args without a shell. Returns (returncode, output, timed_out).

    The child runs in its own process group so the whole group is killed
    on timeout.
    """
    if timeout <= 0:
        return -1, "no time left before the run deadline", True
    os.makedirs(env.get("TMPDIR", cwd), exist_ok=True)
    try:
        proc = subprocess.Popen(
            args,
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    except OSError as exc:
        return -1, f"failed to start {args[0]}: {exc}", False
    try:
        out, _ = proc.communicate(timeout=timeout)
        return proc.returncode, out.decode("utf-8", "replace"), False
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            proc.kill()
        out, _ = proc.communicate()
        text = out.decode("utf-8", "replace") if out else ""
        return -1, text + f"\n[killed after {timeout:.0f}s timeout]", True


def _missing_module(args: list[str]) -> str | None:
    """If args is `<python> -m <module>` and the module is absent, return its name."""
    if len(args) >= 3 and args[0] == sys.executable and args[1] == "-m":
        module = args[2]
        if importlib.util.find_spec(module) is None:
            return module
    return None


def run_poc(label: str, cfg: dict, src_dir: str, env: dict, deadline: float, log: StepLog) -> str:
    """exit 0 -> EXPLOITABLE; 2-5, timeout, start failure -> ERROR; else NOT_EXPLOITABLE."""
    missing = _missing_module(cfg["poc_cmd"])
    if missing:
        log.add(f"--- {label} ---\nmodule '{missing}' is not installed in the sandbox image")
        return POC_ERROR
    rc, out, timed_out = run_limited(cfg["poc_cmd"], src_dir, env, remaining(deadline))
    log.add_output(f"{label}: {' '.join(shlex.quote(a) for a in cfg['poc_cmd'][1:])} (exit {rc})", out)
    if timed_out or rc < 0:
        return POC_ERROR
    if rc == 0:
        return EXPLOITABLE
    if rc in (2, 3, 4, 5):
        # pytest: interrupted, internal error, usage error, no tests collected.
        # unittest (3.12+): 5 = no tests ran.
        return POC_ERROR
    return NOT_EXPLOITABLE


def parse_test_counts(output: str) -> tuple[int | None, int | None]:
    """Return (tests_total, tests_failed) from pytest or unittest output."""
    summary = None
    for line in output.splitlines():
        if RE_PYTEST_SUMMARY.search(line):
            summary = line
    if summary:
        counts: dict[str, int] = {}
        for num, kind in RE_PYTEST_COUNT.findall(summary):
            kind = "errors" if kind.startswith("error") else kind
            counts[kind] = counts.get(kind, 0) + int(num)
        failed = counts.get("failed", 0) + counts.get("errors", 0)
        total = sum(counts.get(k, 0) for k in ("passed", "failed", "errors", "skipped", "xfailed", "xpassed"))
        return total, failed

    ran = RE_UNITTEST_RAN.findall(output)
    if ran:
        total = int(ran[-1])
        failed = 0
        m = RE_UNITTEST_FAILED.findall(output)
        if m:
            for part in m[-1].split(","):
                key, _, val = part.strip().partition("=")
                if key in ("failures", "errors", "unexpected successes") and val.isdigit():
                    failed += int(val)
        return total, failed
    return None, None


def run_unit_tests(cfg: dict, src_dir: str, env: dict, deadline: float, log: StepLog):
    missing = _missing_module(cfg["unit_cmd"])
    if missing:
        log.add(f"--- unit tests ---\nmodule '{missing}' is not installed in the sandbox image")
        return False, None, None
    rc, out, timed_out = run_limited(cfg["unit_cmd"], src_dir, env, remaining(deadline))
    log.add_output(f"unit tests: {' '.join(shlex.quote(a) for a in cfg['unit_cmd'][1:])} (exit {rc})", out)
    total, failed = parse_test_counts(out)
    passed = (rc == 0) and not timed_out
    return passed, total, failed


# --------------------------------------------------------------------------
# Verdict and result
# --------------------------------------------------------------------------


def compute_verdict(poc_before, poc_after, unit_tests_passed, infra_error: bool) -> str:
    """Verdict rules from NAMING.md.

    ERROR also covers poc_before == ERROR: the PoC could not be run, so
    nothing was reproduced or disproved.
    """
    if infra_error or poc_before == POC_ERROR:
        return VERDICT_ERROR
    if poc_before != EXPLOITABLE:
        return POC_NOT_REPRODUCED
    if poc_after == NOT_EXPLOITABLE and unit_tests_passed:
        return PATCH_VERIFIED
    return PATCH_FAILED


def build_result(state: dict, log: StepLog) -> dict:
    verdict = state["verdict"]
    severity = "ERROR" if verdict == VERDICT_ERROR else "INFO"
    message = f"Sandbox run {state.get('run_id') or 'unknown'}: {verdict}"
    if state.get("error"):
        message += f" ({state['error']})"
    result = {
        "severity": severity,
        "message": truncate(message, 500),
        "event_type": EVENT_TYPE,
        "run_id": state.get("run_id"),
        "execution_name": state.get("execution_name"),
        "repository": state.get("repository"),
        "commit_sha": state.get("commit_sha"),
        "patch_ref": state.get("patch_ref"),
        "issue_id": state.get("issue_id"),
        "poc_test": state.get("poc_test"),
        "started_at": state.get("started_at"),
        "finished_at": state.get("finished_at"),
        "poc_before": state.get("poc_before"),
        "poc_after": state.get("poc_after"),
        "patch_applied": bool(state.get("patch_applied")),
        "unit_tests_passed": bool(state.get("unit_tests_passed")),
        "tests_total": state.get("tests_total"),
        "tests_failed": state.get("tests_failed"),
        "verdict": verdict,
        "log_excerpt": log.excerpt(),
        "logging.googleapis.com/labels": {"component": COMPONENT},
    }
    assert tuple(result) == RESULT_FIELDS
    return result


def run(env: dict[str, str] | None = None) -> tuple[int, dict]:
    """Run one validation. Returns (exit_code, result dict). Does not print."""
    env = dict(os.environ if env is None else env)
    log = StepLog()
    started = time.monotonic()
    execution_name = env.get("CLOUD_RUN_EXECUTION") or None
    state: dict = {
        "run_id": _clean(env.get("RUN_ID")) or None,
        "execution_name": _clean(execution_name),
        "repository": _clean(env.get("REPOSITORY")),
        "commit_sha": _clean(env.get("COMMIT_SHA"), 64),
        "patch_ref": _clean(env.get("PATCH_URI") or "none", 1024),
        "issue_id": _clean(env.get("ISSUE_ID")) or None,
        "poc_test": _clean(env.get("POC_TEST") or DEFAULT_POC_TEST, 512),
        "started_at": utc_now(),
        "finished_at": None,
        "poc_before": None,
        "poc_after": None,
        "patch_applied": False,
        "unit_tests_passed": False,
        "tests_total": None,
        "tests_failed": None,
        "verdict": VERDICT_ERROR,
        "error": None,
    }
    work_root = None
    infra_error = False
    try:
        cfg = load_config(env)
        state.update(
            run_id=cfg["run_id"],
            repository=cfg["repository"],
            commit_sha=cfg["commit_sha"],
            issue_id=cfg["issue_id"] or None,
            poc_test=cfg["poc_test"],
            patch_ref=cfg["patch_uri"],
        )
        deadline = started + cfg["timeout"]
        log.add(f"run_id={cfg['run_id']} repository={cfg['repository']} commit={cfg['commit_sha']}")

        work_root = tempfile.mkdtemp(prefix="sandbox-")
        src_parent = os.path.join(work_root, "src")
        os.makedirs(src_parent)

        log_progress(f"Fetching source {cfg['source_uri']}")
        tar_path = os.path.join(work_root, "source.tar.gz")
        fetch_input(cfg["source"], tar_path, MAX_SOURCE_BYTES, min(remaining(deadline), 120))
        src_dir = safe_extract(tar_path, src_parent)
        log.add("source extracted")

        patch_file = None
        if cfg["patch"] is not None:
            log_progress(f"Fetching patch {cfg['patch_uri']}")
            patch_file = os.path.join(work_root, "fix.patch")
            fetch_input(cfg["patch"], patch_file, MAX_PATCH_BYTES, min(remaining(deadline), 120))
            with open(patch_file, "r", encoding="utf-8", errors="replace") as fh:
                check_patch_paths(fh.read())

        cenv = child_env(work_root, src_dir)

        log_progress("Running PoC before patch")
        state["poc_before"] = run_poc("poc before patch", cfg, src_dir, cenv, deadline, log)

        if patch_file is not None:
            log_progress("Applying patch")
            state["patch_applied"] = apply_patch(src_dir, patch_file, cenv, deadline, log)
            if state["patch_applied"]:
                log_progress("Running PoC after patch")
                state["poc_after"] = run_poc("poc after patch", cfg, src_dir, cenv, deadline, log)
            else:
                log.add("patch did not apply; PoC after patch not run")
        else:
            log.add("PATCH_URI=none; reproduce-only run")

        log_progress("Running unit tests")
        passed, total, failed = run_unit_tests(cfg, src_dir, cenv, deadline, log)
        state.update(unit_tests_passed=passed, tests_total=total, tests_failed=failed)
    except (InputError, InfraError) as exc:
        infra_error = True
        state["error"] = str(exc)
        log.add(f"ERROR: {exc}")
    except Exception as exc:  # any unexpected failure is reported, not raised
        infra_error = True
        state["error"] = f"unexpected {type(exc).__name__}: {exc}"
        log.add(f"ERROR: {state['error']}")
    finally:
        if work_root:
            shutil.rmtree(work_root, ignore_errors=True)

    state["verdict"] = compute_verdict(
        state["poc_before"], state["poc_after"], state["unit_tests_passed"], infra_error
    )
    if state["verdict"] == VERDICT_ERROR and not state["error"] and state["poc_before"] == POC_ERROR:
        state["error"] = "PoC could not be run before the patch"
    state["finished_at"] = utc_now()
    result = build_result(state, log)
    return (1 if state["verdict"] == VERDICT_ERROR else 0), result


def main() -> int:
    env = dict(os.environ)
    if not env.get("RUN_ID"):
        # Allow ad-hoc executions; production callers always set RUN_ID.
        env["RUN_ID"] = env.get("CLOUD_RUN_EXECUTION") or f"local-{uuid.uuid4().hex[:12]}"
    code, result = run(env)
    sys.stdout.write(json.dumps(result, separators=(",", ":")) + "\n")
    sys.stdout.flush()
    return code


if __name__ == "__main__":
    sys.exit(main())
