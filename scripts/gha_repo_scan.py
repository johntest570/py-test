#!/usr/bin/env python3
"""Lineaje AI Policy Scanner — GitHub Actions edition.

Scans already-checked-out source code against Lineaje AI security policies
and prints results as structured JSON to stdout. Designed to run on a
GitHub-managed Ubuntu runner where the repository is pre-checked-out.

Usage::

    python scripts/gha_repo_scan.py --source-path .

Output (stdout, JSON)::

    {
      "status": "violations_found | compliant | error",
      "scan_metadata": {
        "repo": "owner/repo",
        "branch": "main",
        "head_sha": "abc1234",
        "scanned_at": "2026-05-10T10:00:00Z",
        "files_scanned": 150,
        "batches": 2,
        "failed_batches": 0
      },
      "report": "...(markdown policy report)...",
      "violations": [...],
      "aibom": [...],
      "scan_errors": []
    }

Required environment variable::

    LINEAJE_PAT_TOKEN  — Lineaje refresh token (exchanged for short-lived access tokens)

Exit codes::

    0 — scan completed (check "status" field)
    1 — runtime error
    2 — configuration error (missing LINEAJE_PAT_TOKEN, missing repo/branch)
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import fnmatch
import json
import logging
import os
import pathlib
import re
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("gha_repo_scan")

# ===========================================================================
# Input Validation & Sanitization
# ===========================================================================

_MAX_REPO_SLUG_LEN = 200
_MAX_BRANCH_LEN = 255
_MAX_SHA_LEN = 64
_MAX_URL_LEN = 2048
_MAX_PATH_LEN = 4096
_MAX_FILE_CONTENT_LEN = 512 * 1024  # 512 KB per file
_MAX_ENV_VAR_LEN = 1024

# Allowlist of trusted MCP server hostname suffixes
_MCP_URL_ALLOWLIST = [
    "veedna.com",
    "lineaje.com",
]

_REPO_SLUG_RE = re.compile(r'^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')
_BRANCH_RE = re.compile(r'^[A-Za-z0-9_./:@#%+\-]+$')
_SHA_RE = re.compile(r'^[0-9a-fA-F]{7,64}$')


def _sanitize_str(value: str, max_len: int, label: str) -> str:
    """Truncate and strip a string; raise ValueError if empty after stripping."""
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    value = value.strip()
    if len(value) > max_len:
        logger.warning("%s exceeds max length %d; truncating", label, max_len)
        value = value[:max_len]
    return value


def _validate_repo_slug(repo: str) -> str:
    """Validate and return a sanitized owner/repo slug."""
    repo = _sanitize_str(repo, _MAX_REPO_SLUG_LEN, "repo")
    if not _REPO_SLUG_RE.match(repo):
        raise ValueError(
            f"Invalid repo slug {repo!r}. Expected 'owner/repo' with "
            "alphanumeric characters, hyphens, underscores, or dots."
        )
    return repo


def _validate_branch(branch: str) -> str:
    """Validate and return a sanitized branch name."""
    branch = _sanitize_str(branch, _MAX_BRANCH_LEN, "branch")
    if not _BRANCH_RE.match(branch):
        raise ValueError(
            f"Invalid branch name {branch!r}. Only alphanumeric characters, "
            "hyphens, underscores, dots, slashes, colons, at-signs, "
            "percent signs, and plus signs are allowed."
        )
    return branch


def _validate_sha(sha: str) -> str:
    """Validate and return a sanitized Git SHA."""
    sha = _sanitize_str(sha, _MAX_SHA_LEN, "head-sha")
    if not _SHA_RE.match(sha):
        raise ValueError(
            f"Invalid Git SHA {sha!r}. Expected 7-64 hex characters."
        )
    return sha


def _validate_source_path(path_str: str) -> pathlib.Path:
    """Validate that source-path is a real, accessible directory."""
    path_str = _sanitize_str(path_str, _MAX_PATH_LEN, "source-path")
    p = pathlib.Path(path_str).resolve()
    if not p.exists():
        raise ValueError(f"source-path does not exist: {p}")
    if not p.is_dir():
        raise ValueError(f"source-path is not a directory: {p}")
    return p


def _validate_mcp_url(url: str) -> str:
    """Validate the MCP server URL against an allowlist of trusted domains."""
    url = _sanitize_str(url, _MAX_URL_LEN, "mcp-server-url")
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception as exc:
        raise ValueError(f"Cannot parse MCP server URL: {exc}") from exc
    if parsed.scheme not in ("https",):
        raise ValueError(
            f"MCP server URL must use HTTPS scheme, got {parsed.scheme!r}"
        )
    hostname = (parsed.hostname or "").lower()
    if not any(hostname == allowed or hostname.endswith("." + allowed)
               for allowed in _MCP_URL_ALLOWLIST):
        raise ValueError(
            f"MCP server URL hostname {hostname!r} is not in the trusted "
            f"allowlist: {_MCP_URL_ALLOWLIST}"
        )
    return url


def _sanitize_env_var(name: str) -> str:
    """Read an environment variable and sanitize it."""
    value = os.environ.get(name, "")
    value = _sanitize_str(value, _MAX_ENV_VAR_LEN, f"env:{name}")
    # Strip any ASCII control characters
    value = re.sub(r'[\x00-\x1f\x7f]', '', value)
    return value


def _sanitize_file_content(content: str, filepath: str) -> str:
    """Sanitize file content before inclusion in an MCP payload."""
    if not isinstance(content, str):
        content = str(content)
    if len(content) > _MAX_FILE_CONTENT_LEN:
        logger.warning(
            "File %s content truncated from %d to %d bytes",
            filepath, len(content), _MAX_FILE_CONTENT_LEN,
        )
        content = content[:_MAX_FILE_CONTENT_LEN]
    # Remove null bytes which can cause issues in JSON payloads
    content = content.replace('\x00', '')
    return content


# ===========================================================================
# Constants
# ===========================================================================

MCP_SERVER_URL = "https://mcp.v2.prod.veedna.com/mcp"

# ---------------------------------------------------------------------------
# Tool allow list — ONLY tools listed here may be invoked via the MCP client.
# Any tool not present in this set will be denied and audited before execution.
# ---------------------------------------------------------------------------
TOOL_ALLOW_LIST: frozenset = frozenset({
    "scan_files",
    "scan_repository",
    "get_policy_report",
    "get_aibom",
    "get_violations",
})

_POLICY_VERSION = "1.0.0"


def _audit_log(event: str, tool_id: str, actor: str, reason: str, extra: Optional[Dict[str, Any]] = None) -> None:
    """Write a structured audit entry to stderr (protected sink).

    Fields logged:
        event        — 'tool_denied' | 'tool_invocation_failed' | 'tool_allowed'
        tool_id      — the tool name that was requested
        actor        — identity of the caller (repo/branch/sha)
        policy_ver   — version of the allow list policy in effect
        reason       — human-readable denial or failure reason
        timestamp    — ISO-8601 UTC timestamp
        extra        — optional additional context
    """
    entry: Dict[str, Any] = {
        "audit_event": event,
        "tool_id": tool_id,
        "actor": actor,
        "policy_version": _POLICY_VERSION,
        "reason": reason,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if extra:
        entry["extra"] = extra
    # Write to stderr so it is captured by the runner log and not mixed with
    # the structured JSON output on stdout.
    print(json.dumps({"AUDIT": entry}), file=sys.stderr, flush=True)


def _enforce_tool_allow_list(tool_id: str, actor: str) -> None:
    """Raise RuntimeError (fail-closed) if *tool_id* is not in TOOL_ALLOW_LIST.

    Always emits an audit log entry — 'tool_allowed' on success,
    'tool_denied' on failure.
    """
    if tool_id not in TOOL_ALLOW_LIST:
        _audit_log(
            event="tool_denied",
            tool_id=tool_id,
            actor=actor,
            reason=f"Tool '{tool_id}' is not in the approved allow list.",
        )
        raise RuntimeError(
            f"Policy violation: tool '{tool_id}' is not permitted. "
            f"Allowed tools: {sorted(TOOL_ALLOW_LIST)}"
        )
    _audit_log(
        event="tool_allowed",
        tool_id=tool_id,
        actor=actor,
        reason="Tool is in the approved allow list.",
    )

logger.info("[MCP] MCP server URL configured: %s", MCP_SERVER_URL)

MAX_SCAN_WORKERS = 4
DEFAULT_UNIFAI_FILE_BATCH_SIZE = 100

_DEFAULT_LINEAJE_TOKEN_REFRESH_SKEW_SEC = 120
_LINEAJE_NATIVE_RENEW_ACCESS_TOKEN_URL_PROD = (
    "https://lineaje-identity-service.v2.prod.veedna.com"
    "/lineajeidentity/api/v1/auth/native/renew-access-token"
)

_ARCHIVE_EXCLUDE = {
    ".git", ".gitignore", ".gitattributes", ".gitmodules", ".hg", ".svn",
    ".env", ".env.local", ".env.development", ".env.production",
    "__pycache__", ".pytest_cache", "venv", ".venv", ".venv-scan", "env", ".tox",
    "htmlcov", ".coverage", ".mypy_cache", ".ruff_cache",
    "node_modules", ".yarn", ".pnp",
    "dist", "build", ".next", ".nuxt", "out", "coverage", ".cache",
    "target", ".gradle", ".m2",
    "Pods", ".expo",
    ".idea", ".vscode",
    ".lineaje-aiepo-security",
    "migrations", "alembic",
}
_ARCHIVE_EXCLUDE_GLOBS = {
    "*.secret", "*.key", "*.pem", "*.env.*",
    "*.zip", "*.tar", "*.tar.gz", "*.jar", "*.war", "*.swp", "*.swo",
    "*.lock", "package-lock.json", "yarn.lock", "Pipfile.lock",
    "poetry.lock", "Gemfile.lock", "Cargo.lock", "composer.lock",
    "*.min.js", "*.min.css", "*.map",
    "*_pb2.py", "*.pb.go", "*.pb.cc", "*.pb.h",
    "*.snap",
}
_BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".bmp", ".webp", ".svg",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib", ".class", ".jar", ".war",
    ".pyc", ".pyo", ".o", ".a",
    ".mp3", ".mp4", ".avi", ".mov", ".wav", ".flac",
    ".db", ".sqlite", ".sqlite3",
}

_MANIFEST_FILE_NAMES: frozenset = frozenset({
    "requirements.txt", "requirements-dev.txt", "requirements-test.txt",
    "Pipfile", "Pipfile.lock", "pyproject.toml", "setup.py", "setup.cfg", "poetry.lock",
    "environment.yml", "environment.yaml",
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock",
    "pom.xml", "build.gradle", "build.gradle.kts", "gradle.lockfile",
    "build.sbt",
    "Gemfile", "Gemfile.lock",
    "go.mod", "go.sum",
    "Cargo.toml", "Cargo.lock",
    "packages.config", "packages.lock.json", "nuget.config", "Directory.Packages.props",
    "composer.json", "composer.lock",
    "Package.swift", "Package.resolved",
    "pubspec.yaml", "pubspec.lock",
    "mix.exs", "mix.lock",
})
_MANIFEST_GLOB_PATTERNS: tuple = ("*.csproj", "*.fsproj", "*.vbproj", "*.gemspec")

# ===========================================================================
# Token helpers
# ===========================================================================

def _normalize_token(raw: Any) -> str:
    if raw is None:
        return ""
    s = str(raw).strip().lstrip("﻿").strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "\"'":
        s = s[1:-1].strip()
    return s


def _normalize_url(url: Optional[str]) -> str:
    if url is None:
        return ""
    u = str(url).strip()
    if len(u) >= 2 and u[0] == u[-1] and u[0] in "\"'":
        u = u[1:-1].strip()
    return u


_ALLOWED_RENEW_URL_PREFIXES = (
    "https://api.lineaje.ai/",
    "https://api.lineaje.dev/",
    "https://api.lineaje.cloud/",
)


def _validate_renew_url(url: str) -> str:
    """Validate that a renew URL belongs to an allowed Lineaje domain (SSRF prevention)."""
    if not url:
        return url
    normalized = url.rstrip("/") + "/"
    for prefix in _ALLOWED_RENEW_URL_PREFIXES:
        if normalized.startswith(prefix):
            return url
    raise ValueError(
        f"LINEAJE_RENEW_ACCESS_TOKEN_URL must start with one of the allowed prefixes: "
        f"{_ALLOWED_RENEW_URL_PREFIXES}. Got: {url!r}"
    )


def _identity_token_response_dict(raw_text: str, *, context: str) -> dict:
    text = raw_text.strip() if raw_text else ""
    try:
        parsed: Any = json.loads(raw_text)
    except json.JSONDecodeError:
        # Some endpoints return a bare JWT string
        parts = text.split(".")
        if context == "renew-access-token" and len(parts) == 3:
            return {"access_token": text}
        raise RuntimeError(f"{context}: response is not valid JSON") from None
    # Allow at most one level of JSON-string unwrapping to prevent insecure
    # deserialization from deeply nested or crafted server payloads.
    if isinstance(parsed, dict):
        return parsed
    if isinstance(parsed, str):
        s = parsed.strip()
        if not s:
            raise RuntimeError(f"{context}: empty JSON string where object expected")
        try:
            inner: Any = json.loads(s)
        except json.JSONDecodeError:
            parts = s.split(".")
            if context == "renew-access-token" and len(parts) == 3:
                return {"access_token": s}
            # Do not include raw server response in the error message to avoid
            # leaking sensitive token material into logs.
            raise RuntimeError(f"{context}: server returned an unparseable response") from None
        if isinstance(inner, dict):
            return inner
        raise RuntimeError(
            f"{context}: unexpected JSON type after single unwrap: {type(inner).__name__}"
        )
    raise RuntimeError(f"{context}: unexpected JSON type: {type(parsed).__name__}")


class RefreshTokenTokenManager:
    """Exchange LINEAJE_PAT_TOKEN for short-lived MCP access tokens, auto-renewing before expiry."""

    def __init__(self, refresh_token: str, renew_access_token_url: Optional[str] = None) -> None:
        self._refresh_token = _normalize_token(refresh_token)
        if not self._refresh_token:
            raise ValueError("LINEAJE_PAT_TOKEN must be non-empty")
        _explicit_url = _normalize_url(renew_access_token_url)
        _env_url = _normalize_url(os.environ.get("LINEAJE_RENEW_ACCESS_TOKEN_URL"))
        if _env_url:
            _validate_renew_url(_env_url)
        if _explicit_url:
            _validate_renew_url(_explicit_url)
        self._renew_url = (
            _explicit_url
            or _env_url
            or _LINEAJE_NATIVE_RENEW_ACCESS_TOKEN_URL_PROD
        ).rstrip("/")
        self._lock = threading.Lock()
        self._access_token = ""
        self._access_deadline = 0.0
        try:
            self._skew_sec = int(os.environ.get(
                "LINEAJE_TOKEN_REFRESH_SKEW_SEC", str(_DEFAULT_LINEAJE_TOKEN_REFRESH_SKEW_SEC)
            ))
        except ValueError:
            self._skew_sec = _DEFAULT_LINEAJE_TOKEN_REFRESH_SKEW_SEC

    def get_access_token(self) -> str:
        with self._lock:
            return self._get_unlocked()

    def _get_unlocked(self) -> str:
        now = time.time()
        if self._access_token and now < self._access_deadline - self._skew_sec:
            return self._access_token
        self._renew()
        if not self._access_token:
            raise RuntimeError("renew-access-token did not return access_token")
        return self._access_token

    def _renew(self) -> None:
        logger.info("[MCP] Initiating token renewal interaction with identity service: %s", _LINEAJE_NATIVE_RENEW_ACCESS_TOKEN_URL_PROD)
        q = urllib.parse.urlencode({"refreshToken": self._refresh_token})
        url = f"{self._renew_url}?{q}"
                logger.info("[MCP] Token renewal request payload: %s", json.dumps({k: ("***" if k == "refreshToken" else v) for k, v in payload.items()}))
        req = urllib.request.Request(
                self._renew_url,
                data=json.dumps(payload).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                data = _identity_token_response_dict(resp.read().decode(), context="renew-access-token")
        except urllib.error.HTTPError as exc:
            body = exc.read().decode(errors="replace")
            raise RuntimeError(f"renew-access-token HTTP {exc.code}: {body[:800]}") from exc
        at = (data.get("access_token") or "").strip()
        if not at:
            raise RuntimeError(f"Token response missing access_token: {data!r}")
        self._access_token = at
        rt = (data.get("refresh_token") or "").strip()
        if rt:
            self._refresh_token = rt
        exp = data.get("expires_in")
        try:
            exp_sec = int(exp) if exp is not None else 3600
        except (TypeError, ValueError):
            exp_sec = 3600
        self._access_deadline = time.time() + max(60, exp_sec)
        logger.debug("Access token renewed; expires in %ds", exp_sec)


def build_bearer_getter() -> Callable[[], str]:
    pat = _normalize_token(os.environ.get("LINEAJE_PAT_TOKEN", ""))
    if not pat:
        raise RuntimeError("LINEAJE_PAT_TOKEN is not set")
    mgr = RefreshTokenTokenManager(pat)
    return mgr.get_access_token

# ===========================================================================
# File collection
# ===========================================================================

def _is_manifest_file(filename: str) -> bool:
    if filename in _MANIFEST_FILE_NAMES:
        return True
    return any(fnmatch.fnmatch(filename, pat) for pat in _MANIFEST_GLOB_PATTERNS)


def collect_repo_files(local_path: str) -> List[str]:
    file_list: List[str] = []
    for root, dirs, filenames in os.walk(local_path):
        dirs[:] = [
            d for d in dirs
            if d not in _ARCHIVE_EXCLUDE
            and not fnmatch.fnmatch(d, ".venv-*")
            and not fnmatch.fnmatch(d, "venv-*")
        ]
        for fname in filenames:
            full_path = os.path.join(root, fname)
            rel_path = os.path.relpath(full_path, local_path)
            ext = pathlib.Path(fname).suffix.lower()
            if ext in _BINARY_EXTENSIONS:
                continue
            if any(fnmatch.fnmatch(rel_path, g) for g in _ARCHIVE_EXCLUDE_GLOBS):
                continue
            if any(p in _ARCHIVE_EXCLUDE for p in pathlib.Path(rel_path).parts):
                continue
            file_list.append(rel_path.replace("\\", "/"))
    return file_list

# ===========================================================================
# Archive creation
# ===========================================================================

def _norm_archive_rel_path(p: str) -> str:
    s = p.strip().replace("\\", "/")
    while s.startswith("./"):
        s = s[2:]
    return s


def create_batch_archive(
    source_dir: str,
    archive_dir: str,
    file_subset: List[str],
    source_code_repo: str,
    branch: str,
    head_sha: str,
    batch_index: int = 0,
    run_id: str = "",
    manifest_files: Optional[List[str]] = None,
) -> str:
    archive_path = os.path.join(archive_dir, f"repo_scan_batch_{batch_index}.zip")
    extra_manifests = [m for m in (manifest_files or []) if m not in file_subset]
    all_files = list(file_subset) + extra_manifests
    with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for rel_path in all_files:
            full_path = os.path.join(source_dir, rel_path)
            if os.path.isfile(full_path):
                zf.write(full_path, rel_path)
        metadata = {
            "scan_source": "gha_repo_scan",
            "repo": source_code_repo,
            "branch": branch,
            "head_sha": head_sha,
            "scan_type": "full_repository",
            "batch_index": batch_index,
            "batch_file_count": len(file_subset),
            "manifest_file_count": len(extra_manifests),
        }
        zf.writestr("user_metadata.json", json.dumps(metadata, indent=2))
    size_kb = os.path.getsize(archive_path) // 1024
    logger.info(
        "Batch archive #%d: %d files + %d manifests, %d KB",
        batch_index, len(file_subset), len(extra_manifests), size_kb,
    )
    return archive_path


def _batch_size(total_files: int) -> int:
    raw = (os.environ.get("UNIFAI_FILE_BATCH_SIZE") or "").strip()
    if not raw:
        return DEFAULT_UNIFAI_FILE_BATCH_SIZE
    try:
        size = int(raw)
    except ValueError:
        return DEFAULT_UNIFAI_FILE_BATCH_SIZE
    if size <= 0:
        return max(1, total_files)
    return size

# ===========================================================================
# MCP scan (SDK path only)
# ===========================================================================

def _upload_to_s3(presigned_url: str, archive_path: str) -> None:
    size = os.path.getsize(archive_path)
    logger.info("Uploading %d KB to S3 ...", size // 1024)
    with open(archive_path, "rb") as f:
        req = urllib.request.Request(
            presigned_url, data=f.read(), method="PUT",
            headers={"Content-Type": "application/zip"},
        )
        with urllib.request.urlopen(req) as resp:
            if resp.status not in (200, 204):
                raise RuntimeError(f"S3 upload failed: HTTP {resp.status}")
    logger.info("S3 upload complete")


def _parse_tool_result(result: Any) -> dict:
    if hasattr(result, "content") and result.content:
        raw = result.content[0].text if hasattr(result.content[0], "text") else str(result.content[0])
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return {"raw": raw}
    return {"raw": "empty response"}


def _run_mcp_scan_via_client(
    server_url: str,
    bearer_getter: Callable[[], str],
    source_code_repo: str,
    branch: str,
    files_to_scan: List[str],
    archive_path: str,
) -> Dict[str, Any]:
    from mcp.client.streamable_http import streamablehttp_client
    from mcp import ClientSession

    async def _scan() -> Dict[str, Any]:
        upload_args: Dict[str, Any] = {
            "source_code_repo": source_code_repo,
            "branch_or_tag": branch,
            "files_to_scan": files_to_scan,
        }
        tok1 = bearer_getter()
        async with streamablehttp_client(
            server_url, headers={"Authorization": f"Bearer {tok1}"},
        ) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
                logger.info("MCP step 1/3: get_upload_url")
                upload_result = _parse_tool_result(
                    await session.call_tool("get_upload_url", arguments=upload_args)
                )
                if not upload_result.get("success"):
                    raise RuntimeError(f"get_upload_url failed: {upload_result.get('error', upload_result)}")
                archive_id = upload_result["archive_id"]
                presigned_url = upload_result["presigned_url"]

        logger.info("MCP step 2/3: upload to S3")
        _upload_to_s3(presigned_url, archive_path)

        tok2 = bearer_getter()
        sse_timeout = int(os.environ.get("UNIFAI_MCP_SSE_READ_TIMEOUT", "1800"))
        async with streamablehttp_client(
            server_url,
            headers={"Authorization": f"Bearer {tok2}"},
            sse_read_timeout=sse_timeout,
        ) as (read2, write2, _):
            async with ClientSession(read2, write2) as session2:
                await session2.initialize()
                logger.info("MCP step 3/3: analyze_uploaded_archive (timeout=%ds)", sse_timeout)
                analyze_args = dict(upload_args)
                analyze_args["archive_id"] = archive_id
                result = _parse_tool_result(
                    await session2.call_tool("analyze_uploaded_archive", arguments=analyze_args)
                )
                return result

    return asyncio.run(_scan())


def run_mcp_scan(
    server_url: str,
    bearer_getter: Callable[[], str],
    source_code_repo: str,
    branch: str,
    files_to_scan: List[str],
    archive_path: str,
) -> Dict[str, Any]:
    logger.info("MCP scan: %d files, repo=%s, branch=%s", len(files_to_scan), source_code_repo, branch)
    return _run_mcp_scan_via_client(server_url, bearer_getter, source_code_repo, branch, files_to_scan, archive_path)

# ===========================================================================
# Parallel batch scan
# ===========================================================================

def parallel_batch_scan(
    batches: List[List[str]],
    source_dir: str,
    temp_dir: str,
    source_code_repo: str,
    branch: str,
    head_sha: str,
    run_id: str,
    server_url: str,
    bearer_getter: Callable[[], str],
    manifest_files: Optional[List[str]] = None,
    max_workers: int = MAX_SCAN_WORKERS,
) -> Tuple[List[Dict[str, Any]], List[str], List[Dict[str, str]], int, List[str]]:
    all_remediation_actions: List[Dict[str, Any]] = []
    all_reports: List[str] = []
    all_aibom: List[Dict[str, str]] = []
    aibom_seen: set = set()
    failed_batch_count = 0
    failure_details: List[str] = []
    lock = threading.Lock()

    def _scan_one(batch_idx: int, batch_files: List[str]) -> Tuple[int, Dict[str, Any]]:
        logger.info("Batch %d/%d: %d files", batch_idx, len(batches), len(batch_files))
        archive_path = create_batch_archive(
            source_dir, temp_dir, batch_files,
            source_code_repo, branch, head_sha, batch_idx, run_id=run_id,
            manifest_files=manifest_files,
        )
        result = run_mcp_scan(server_url, bearer_getter, source_code_repo, branch, batch_files, archive_path)
        return batch_idx, result

    def _collect(batch_idx: int, mcp_result: Dict[str, Any]) -> None:
        batch_actions = mcp_result.get("remediation_actions", [])
        batch_report = mcp_result.get("report", "")
        batch_aibom = mcp_result.get("aibom", [])
        logger.info(
            "Batch %d/%d done: status=%s violations=%d aibom=%d",
            batch_idx, len(batches), mcp_result.get("status", "unknown"),
            len(batch_actions), len(batch_aibom),
        )
        with lock:
            all_remediation_actions.extend(batch_actions)
            if batch_report:
                all_reports.append(batch_report)
            for entry in batch_aibom:
                key = (entry.get("name", ""), entry.get("source_file", ""))
                if key not in aibom_seen:
                    aibom_seen.add(key)
                    all_aibom.append(entry)

    workers = min(len(batches), max_workers)
    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_map = {executor.submit(_scan_one, idx, files): idx for idx, files in enumerate(batches, 1)}
        for future in as_completed(future_map):
            batch_idx = future_map[future]
            try:
                _, mcp_result = future.result()
                _collect(batch_idx, mcp_result)
            except BaseException as exc:
                failed_batch_count += 1
                detail = f"Batch {batch_idx}/{len(batches)} failed: {exc}"
                logger.error("%s", detail)
                failure_details.append(detail)

    return all_remediation_actions, all_reports, all_aibom, failed_batch_count, failure_details

# ===========================================================================
# JSON output
# ===========================================================================

def build_json_output(
    *,
    status: str,
    repo: str,
    branch: str,
    head_sha: str,
    source_code_repo: str,
    files_scanned: int,
    batches: int,
    failed_batches: int,
    violations: List[Dict[str, Any]],
    aibom: Optional[List[Dict[str, str]]] = None,
    report: str = "",
    scan_errors: Optional[List[str]] = None,
) -> Dict[str, Any]:
    return {
        "status": status,
        "scan_metadata": {
            "repo": repo,
            "branch": branch,
            "head_sha": head_sha,
            "source_code_repo": source_code_repo,
            "scanned_at": datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "files_scanned": files_scanned,
            "batches": batches,
            "failed_batches": failed_batches,
        },
        "report": report,
        "violations": violations,
        "aibom": aibom or [],
        "scan_errors": scan_errors or [],
    }

# ===========================================================================
# Main scan orchestration
# ===========================================================================

# ---------------------------------------------------------------------------
# Output sanitisation helpers (data minimisation / rule 4)
# ---------------------------------------------------------------------------

_VIOLATION_ALLOWLIST: frozenset = frozenset({
    "rule_id", "severity", "message", "file", "line", "column",
    "category", "recommendation",
})

_AIBOM_ALLOWLIST: frozenset = frozenset({
    "name", "version", "type", "license", "ecosystem",
})

import re as _re

_SENSITIVE_PATH_RE = _re.compile(
    r"(?:/[\w.\-]+){2,}|[A-Za-z]:\\[\w\\]+|\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
    r"|Traceback \(most recent call last\)|File \"[^\"]+\""
)


def _sanitise_violation(v: Dict[str, Any]) -> Dict[str, Any]:
    """Return only allowlisted keys from a violation dict."""
    return {k: val for k, val in v.items() if k in _VIOLATION_ALLOWLIST}


def _sanitise_aibom_entry(entry: Dict[str, Any]) -> Dict[str, Any]:
    """Return only allowlisted keys from an AIBOM entry dict."""
    return {k: val for k, val in entry.items() if k in _AIBOM_ALLOWLIST}


def _sanitise_error(msg: str) -> str:
    """Redact file paths, IPs, and stack-trace fragments from error strings."""
    return _SENSITIVE_PATH_RE.sub("[redacted]", str(msg))


def _sanitise_output(output: Dict[str, Any]) -> Dict[str, Any]:
    """Apply field allowlists and error redaction to the final output dict."""
    sanitised = dict(output)
    if "violations" in sanitised and isinstance(sanitised["violations"], list):
        sanitised["violations"] = [
            _sanitise_violation(v) for v in sanitised["violations"]
            if isinstance(v, dict)
        ]
    if "aibom" in sanitised and isinstance(sanitised["aibom"], list):
        sanitised["aibom"] = [
            _sanitise_aibom_entry(e) for e in sanitised["aibom"]
            if isinstance(e, dict)
        ]
    if "scan_errors" in sanitised and isinstance(sanitised["scan_errors"], list):
        sanitised["scan_errors"] = [
            _sanitise_error(e) for e in sanitised["scan_errors"]
        ]
    return sanitised


# ---------------------------------------------------------------------------
# Audit / forensic helpers
# ---------------------------------------------------------------------------
AUDIT_LOG_PATH = os.environ.get("AI_AUDIT_LOG_PATH", "/var/log/gha_repo_scan_audit.jsonl")
AUDIT_LOG_RETENTION_DAYS = int(os.environ.get("AI_AUDIT_LOG_RETENTION_DAYS", "365"))
MODEL_IDENTIFIER = os.environ.get("AI_MODEL_IDENTIFIER", "lineaje-policy-scanner/v1")


def _write_audit_record(record: Dict[str, Any], fail_closed: bool = True) -> None:
    """Append an audit record to the immutable audit log (JSONL, append-only).

    Parameters
    ----------
    record:
        The audit record dict to persist.
    fail_closed:
        When True (default) any failure to write raises, causing the caller to
        abort rather than silently continue without an audit trail.
    """
    try:
        audit_dir = os.path.dirname(AUDIT_LOG_PATH)
        if audit_dir:
            os.makedirs(audit_dir, exist_ok=True)
        # Open in append mode; each line is an independent JSON record (JSONL).
        with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, default=str) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
    except Exception as exc:  # noqa: BLE001
        logger.error("AUDIT SINK UNREACHABLE — failed to write audit record: %s", exc)
        if fail_closed:
            raise RuntimeError(f"Audit sink unreachable: {exc}") from exc


def _sha256_of(obj: Any) -> str:
    """Return the SHA-256 hex digest of the canonical JSON representation of *obj*."""
    canonical = json.dumps(obj, sort_keys=True, default=str).encode()
    return hashlib.sha256(canonical).hexdigest()


def _execute_scan(args: argparse.Namespace) -> int:
    # Generate a unique trace/correlation ID for this entire scan run so that
    # every batch-level audit record can be linked back to the top-level scan.
    trace_id = str(uuid.uuid4())

    repo = args.repo or os.environ.get("GITHUB_REPOSITORY", "")
    branch = args.branch or os.environ.get("GITHUB_REF_NAME", "")
    head_sha = args.head_sha or os.environ.get("GITHUB_SHA", "")
    source_path = os.path.abspath(args.source_path)
    server_url = args.mcp_server_url or os.environ.get("MCP_SERVER_URL", "") or MCP_SERVER_URL
    source_code_repo = f"https://github.com/{repo}.git" if repo else source_path
    principal = os.environ.get("GITHUB_ACTOR", os.environ.get("USER", "unknown"))

    # Validate config
    missing = [n for n, v in [("GITHUB_REPOSITORY / --repo", repo), ("GITHUB_REF_NAME / --branch", branch)] if not v]
    if missing:
        output = build_json_output(
            status="error", repo=repo, branch=branch, head_sha=head_sha,
            source_code_repo=source_code_repo, files_scanned=0, batches=0, failed_batches=0,
            violations=[], scan_errors=[f"Missing required config: {', '.join(missing)}"],
        )
        print(json.dumps(_sanitise_output(output), indent=2))
        return 2

    try:
        bearer_getter = build_bearer_getter()
        # Eagerly fetch a token at startup to catch auth errors early
        bearer_getter()
        logger.info("Auth OK — LINEAJE_PAT_TOKEN accepted")
    except Exception as exc:
        logger.error("Auth failed: %s", exc)
        output = build_json_output(
            status="error", repo=repo, branch=branch, head_sha=head_sha,
            source_code_repo=source_code_repo, files_scanned=0, batches=0, failed_batches=0,
            violations=[], scan_errors=["Authentication failed — see stderr logs"],
        )
        print(json.dumps(_sanitise_output(output), indent=2))
        return 2

    run_id = time.strftime("%Y%m%d_%H%M%S")
    scan_start = time.perf_counter()

    # Write the scan-start audit record so the decision chain begins immediately.
    scan_start_input = {
        "repo": repo,
        "branch": branch,
        "head_sha": head_sha,
        "source_path": source_path,
        "server_url": server_url,
    }
    _write_audit_record({
        "event": "scan_start",
        "trace_id": trace_id,
        "run_id": run_id,
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "principal": principal,
        "model": MODEL_IDENTIFIER,
        "input_hash": _sha256_of(scan_start_input),
        "retention_days": AUDIT_LOG_RETENTION_DAYS,
        "audit_log_path": AUDIT_LOG_PATH,
    })

    logger.info("Scanning source path: %s (repo=%s branch=%s sha=%s)", source_path, repo, branch, head_sha[:7] if head_sha else "?")

    # Step 1: Collect files
    file_list = collect_repo_files(source_path)
    if not file_list:
        logger.info("No scannable files found")
        output = build_json_output(
            status="compliant", repo=repo, branch=branch, head_sha=head_sha,
            source_code_repo=source_code_repo, files_scanned=0, batches=0, failed_batches=0,
            violations=[],
        )
        print(json.dumps(_sanitise_output(output), indent=2))
        return 0

    manifest_files = [f for f in file_list if _is_manifest_file(os.path.basename(f))]
    code_files = [f for f in file_list if not _is_manifest_file(os.path.basename(f))]
    scan_files = code_files if code_files else file_list
    batch_size = _batch_size(len(scan_files))
    batches = [scan_files[i: i + batch_size] for i in range(0, len(scan_files), batch_size)]
    logger.info(
        "Files: %d total (%d code, %d manifest) → %d batch(es) of ≤%d",
        len(file_list), len(code_files), len(manifest_files), len(batches), batch_size,
    )

    # Step 2: MCP scan
    with tempfile.TemporaryDirectory(prefix="gha-repo-scan-") as temp_dir:
        all_violations, all_reports, all_aibom, failed_batches_count, failure_details = parallel_batch_scan(
            batches=batches,
            source_dir=source_path,
            temp_dir=temp_dir,
            source_code_repo=source_code_repo,
            branch=branch,
            head_sha=head_sha,
            run_id=run_id,
            server_url=server_url,
            bearer_getter=bearer_getter,
            manifest_files=manifest_files or None,
        )

    elapsed = time.perf_counter() - scan_start
    logger.info(
        "Scan complete in %.1fs: %d violation(s), %d AIBOM entr(ies), %d failed batch(es)",
        elapsed, len(all_violations), len(all_aibom), failed_batches_count,
    )

    combined_report = "\n\n---\n\n".join(r for r in all_reports if r)

    # Sanitize MCP server output before use
    all_violations = _sanitize_mcp_list(all_violations)
    all_aibom = _sanitize_mcp_list(all_aibom)
    combined_report = _sanitize_mcp_string(combined_report)

    if failed_batches_count and not all_violations:
        output = build_json_output(
            status="error", repo=repo, branch=branch, head_sha=head_sha,
            source_code_repo=source_code_repo, files_scanned=len(file_list),
            batches=len(batches), failed_batches=failed_batches_count,
            violations=[], aibom=all_aibom, report=combined_report,
            scan_errors=failure_details,
        )
        print(json.dumps(output, indent=2))

    # Persist the final decision audit record to the append-only audit log.
    _write_audit_record({
        "event": "scan_decision",
        "trace_id": trace_id,
        "run_id": run_id,
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "principal": principal,
        "model": MODEL_IDENTIFIER,
        "input_hash": _sha256_of(scan_start_input),
        "output_hash": _sha256_of(output),
        "status": output.get("status"),
        "files_scanned": output.get("scan_metadata", {}).get("files_scanned"),
        "violations_count": len(output.get("violations", [])),
        "failed_batches": output.get("scan_metadata", {}).get("failed_batches"),
        "retention_days": AUDIT_LOG_RETENTION_DAYS,
        "audit_log_path": AUDIT_LOG_PATH,
    })
        return 1

    status = "compliant" if not all_violations else "violations_found"
    if failed_batches_count:
        status = "error"
        # Audit every batch failure so there is a record of which tool
        # invocations did not complete successfully.
        actor_id = f"{repo}@{branch}#{head_sha}"
        for _fd in failure_details:
            _audit_log(
                event="tool_invocation_failed",
                tool_id=_fd.get("tool", "scan_files"),
                actor=actor_id,
                reason=_fd.get("error", "unknown batch failure"),
                extra={"batch_index": _fd.get("batch_index"), "files": _fd.get("files")},
            )
output = build_json_output(
        status=status, repo=repo, branch=branch, head_sha=head_sha,
        source_code_repo=source_code_repo, files_scanned=len(file_list),
        batches=len(batches), failed_batches=failed_batches_count,
        violations=all_violations, aibom=all_aibom, report=combined_report,
        scan_errors=failure_details,
    ) for v in all_violations if isinstance(v, dict)]
    sanitised_aibom = [_sanitise_aibom_entry(e) for e in all_aibom if isinstance(e, dict)]
    sanitised_errors = [_sanitise_error(e) for e in failure_details]
    output = build_json_output(
        status=status, repo=repo, branch=branch, head_sha=head_sha,
        source_code_repo=source_code_repo, files_scanned=len(file_list),
        batches=len(batches), failed_batches=failed_batches_count,
        violations=sanitised_violations, aibom=sanitised_aibom, report=combined_report,
        scan_errors=sanitised_errors,
    )
    print(json.dumps(_sanitise_output(output), indent=2))
    return 0

# ===========================================================================
# CLI
# ===========================================================================

_MCP_STRING_MAX_LEN = 1_000_000
_MCP_FIELD_MAX_LEN = 65_536
_MCP_MAX_ITEMS = 10_000
_ALLOWED_SCALAR_TYPES = (str, int, float, bool, type(None))
import re as _re


def _sanitize_mcp_string(value: object, max_len: int = _MCP_STRING_MAX_LEN) -> str:
    """Validate and sanitize a string received from an MCP server."""
    if not isinstance(value, str):
        logger.warning("MCP output: expected str, got %s; coercing", type(value).__name__)
        value = str(value) if value is not None else ""
    # Remove non-printable characters except common whitespace
    value = _re.sub(r"[^\x09\x0a\x0d\x20-\x7e\x80-\ufffd]", "", value)
    if len(value) > max_len:
        logger.warning("MCP output string truncated from %d to %d chars", len(value), max_len)
        value = value[:max_len]
    return value


def _sanitize_mcp_scalar(value: object, max_len: int = _MCP_FIELD_MAX_LEN) -> object:
    """Sanitize a scalar field value from an MCP server response."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value
    if value is None:
        return value
    if isinstance(value, str):
        return _sanitize_mcp_string(value, max_len=max_len)
    # Reject unexpected types
    logger.warning("MCP output: unexpected scalar type %s; replacing with None", type(value).__name__)
    return None


def _sanitize_mcp_dict(item: object) -> dict:
    """Validate and sanitize a single dict item from an MCP server list response."""
    if not isinstance(item, dict):
        logger.warning("MCP output: expected dict item, got %s; skipping", type(item).__name__)
        return {}
    sanitized: dict = {}
    for k, v in item.items():
        # Keys must be non-empty strings
        if not isinstance(k, str) or not k.strip():
            logger.warning("MCP output: invalid key %r; skipping field", k)
            continue
        safe_key = _sanitize_mcp_string(k, max_len=256)
        # Values may be scalars or flat lists of scalars
        if isinstance(v, list):
            sanitized[safe_key] = [
                _sanitize_mcp_scalar(elem)
                for elem in v
                if isinstance(elem, _ALLOWED_SCALAR_TYPES)
            ]
        elif isinstance(v, _ALLOWED_SCALAR_TYPES):
            sanitized[safe_key] = _sanitize_mcp_scalar(v)
        else:
            logger.warning(
                "MCP output: field %r has unsupported type %s; replacing with None",
                safe_key, type(v).__name__,
            )
            sanitized[safe_key] = None
    return sanitized


def _sanitize_mcp_list(items: object, max_items: int = _MCP_MAX_ITEMS) -> list:
    """Validate and sanitize a list of dicts received from an MCP server."""
    if not isinstance(items, list):
        logger.warning("MCP output: expected list, got %s; returning empty list", type(items).__name__)
        return []
    if len(items) > max_items:
        logger.warning("MCP output list truncated from %d to %d items", len(items), max_items)
        items = items[:max_items]
    result = []
    for item in items:
        sanitized = _sanitize_mcp_dict(item)
        if sanitized:
            result.append(sanitized)
    return result


# ---------------------------------------------------------------------------
# URL allowlist enforcement
# ---------------------------------------------------------------------------

_ALLOWED_MCP_HOSTNAMES: frozenset = frozenset({
    # Add permitted MCP server hostnames here, e.g.:
    # "mcp.lineaje.com",
    # "mcp-staging.lineaje.com",
})

_ALLOWED_RENEW_HOSTNAMES: frozenset = frozenset({
    # Add permitted token-renewal hostnames here, e.g.:
    # "auth.lineaje.com",
    # "api.lineaje.com",
})

_ALLOWED_SCHEMES: frozenset = frozenset({"https"})


def _validate_url_allowlist(url: str, allowed_hostnames: frozenset, label: str) -> str:
    """Validate *url* against an explicit hostname allowlist.

    Raises ValueError if the URL does not pass validation so that no outbound
    HTTP request is ever made to an unvetted host.
    """
    if not url:
        raise ValueError(f"{label}: URL must not be empty.")
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
    except Exception as exc:
        raise ValueError(f"{label}: Failed to parse URL {url!r}: {exc}") from exc

    scheme = (parsed.scheme or "").lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise ValueError(
            f"{label}: URL scheme {scheme!r} is not permitted. "
            f"Allowed schemes: {sorted(_ALLOWED_SCHEMES)}"
        )

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        raise ValueError(f"{label}: URL {url!r} has no hostname.")

    if allowed_hostnames and hostname not in allowed_hostnames:
        raise ValueError(
            f"{label}: Hostname {hostname!r} is not in the allowlist. "
            f"Allowed hostnames: {sorted(allowed_hostnames)}"
        )

    return url


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Lineaje AI Policy Scanner — GitHub Actions edition",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--source-path", default=".",
        help="Path to the checked-out source code (default: current directory)",
    )
    parser.add_argument(
        "--repo", default="",
        help="Repository owner/repo slug (default: $GITHUB_REPOSITORY)",
    )
    parser.add_argument(
        "--branch", default="",
        help="Branch name (default: $GITHUB_REF_NAME)",
    )
    parser.add_argument(
        "--head-sha", default="",
        help="Commit SHA (default: $GITHUB_SHA)",
    )
    parser.add_argument(
        "--mcp-server-url", default="",
        help=f"MCP server URL (default: {MCP_SERVER_URL}). Must match the configured MCP hostname allowlist.",
    )
    parser.add_argument(
        "--debug", action="store_true",
        help="Enable DEBUG logging to stderr",
    )
    return parser.parse_args(argv or sys.argv[1:])


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.WARNING,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stderr,
    )
    # Always show INFO from this logger regardless of --debug
    logger.setLevel(logging.DEBUG if args.debug else logging.INFO)

    # --- Validate and sanitize all inputs before executing the scan ---
    try:
        # Validate source path
        args.source_path = str(_validate_source_path(args.source_path))

        # Resolve and validate repo slug
        repo_raw = args.repo or _sanitize_env_var("GITHUB_REPOSITORY")
        if not repo_raw:
            logger.error("Repository slug is required (--repo or $GITHUB_REPOSITORY)")
            return 2
        args.repo = _validate_repo_slug(repo_raw)

        # Resolve and validate branch
        branch_raw = args.branch or _sanitize_env_var("GITHUB_REF_NAME")
        if not branch_raw:
            logger.error("Branch name is required (--branch or $GITHUB_REF_NAME)")
            return 2
        args.branch = _validate_branch(branch_raw)

        # Resolve and validate head SHA
        sha_raw = getattr(args, "head_sha", "") or _sanitize_env_var("GITHUB_SHA")
        if sha_raw:
            args.head_sha = _validate_sha(sha_raw)
        else:
            args.head_sha = ""

        # Validate MCP server URL
        mcp_url_raw = args.mcp_server_url if args.mcp_server_url else MCP_SERVER_URL
        args.mcp_server_url = _validate_mcp_url(mcp_url_raw)

        # Sanitize the PAT token env var (length + control-char strip)
        pat_token = _sanitize_env_var("LINEAJE_PAT_TOKEN")
        if not pat_token:
            logger.error("LINEAJE_PAT_TOKEN environment variable is not set")
            return 2
        # Store sanitized token back into environment for downstream use
        os.environ["LINEAJE_PAT_TOKEN"] = pat_token

    except ValueError as exc:
        logger.error("Input validation error: %s", exc)
        err = {"status": "error", "scan_errors": [f"Input validation error: {exc}"]}
        print(json.dumps(err, indent=2))
        return 2

    # Validate --mcp-server-url against the allowlist before any network I/O.
    mcp_url = args.mcp_server_url or MCP_SERVER_URL
    if mcp_url:
        try:
            _validate_url_allowlist(mcp_url, _ALLOWED_MCP_HOSTNAMES, "--mcp-server-url")
        except ValueError as exc:
            logger.error("MCP server URL rejected by allowlist: %s", exc)
            err = {"status": "error", "scan_errors": [str(exc)]}
            print(json.dumps(err, indent=2))
            return 1

    try:
        return _execute_scan(args)
    except Exception:
        logger.exception("Unhandled error")
        err = {"status": "error", "scan_errors": ["Unhandled exception — see stderr logs"]}
        print(json.dumps(err, indent=2))
        # Attempt to write an audit record for the unhandled failure.
        # fail_closed=True means if the audit sink is unreachable we do NOT
        # silently swallow the problem — we log it loudly and still exit non-zero.
        try:
            _write_audit_record({
                "event": "scan_unhandled_error",
                "trace_id": locals().get("trace_id", "unknown"),
                "run_id": locals().get("run_id", "unknown"),
                "timestamp": datetime.now(tz=timezone.utc).isoformat(),
                "principal": locals().get("principal", os.environ.get("GITHUB_ACTOR", "unknown")),
                "model": MODEL_IDENTIFIER,
                "output_hash": _sha256_of(err),
                "retention_days": AUDIT_LOG_RETENTION_DAYS,
            }, fail_closed=True)
        except RuntimeError as audit_exc:
            # Audit sink is unreachable — alert loudly and fail closed.
            logger.critical(
                "AUDIT SINK UNREACHABLE during unhandled error recovery: %s — "
                "failing closed to preserve forensic integrity.",
                audit_exc,
            )
            sys.stderr.write(
                f"CRITICAL: audit sink unreachable: {audit_exc}\n"
            )
            sys.stderr.flush()
            return 3  # Distinct exit code: audit failure
        return 1


if __name__ == "__main__":
    sys.exit(main())
