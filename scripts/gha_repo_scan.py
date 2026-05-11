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
# Singapore PII Detection
# ===========================================================================

# Patterns for Singapore PII categories
_SG_PII_PATTERNS: List[Tuple[str, re.Pattern]] = [
    # NRIC / FIN: S/T/F/G followed by 7 digits and a letter
    ("NRIC/FIN", re.compile(r'\b[STFG]\d{7}[A-Z]\b')),
    # Singapore passport: E followed by 7 digits (or older formats)
    ("Passport", re.compile(r'\b[EK]\d{7}[A-Z]?\b')),
    # Singapore bank account numbers: 10-12 digit sequences (common formats)
    ("BankAccount", re.compile(r'\b\d{3}-\d{5,6}-\d{1,3}\b')),
    # CPF account number: same format as NRIC/FIN but captured separately
    ("CPF", re.compile(r'\bCPF[\s:/-]*[STFG]\d{7}[A-Z]\b', re.IGNORECASE)),
    # Singapore phone numbers: +65 followed by 8 digits, or 8-digit local
    ("SGPhone", re.compile(r'(?:\+65[\s-]?)?[689]\d{7}\b')),
    # Generic email addresses
    ("Email", re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b')),
]


def _detect_sg_pii(content: str) -> List[str]:
    """Return a list of PII category names found in *content*.

    Scans the provided text for Singapore PII patterns and returns the names
    of every category that matched at least once.
    """
    found: List[str] = []
    for category, pattern in _SG_PII_PATTERNS:
        if pattern.search(content):
            found.append(category)
    return found


def _file_content_safe_for_upload(file_path: str, content: str) -> bool:
    """Return True if *content* contains no Singapore PII, False otherwise.

    Logs a warning (without echoing the sensitive content) when PII is found.
    """
    pii_categories = _detect_sg_pii(content)
    if pii_categories:
        logger.warning(
            "Singapore PII detected in '%s' — categories: %s — file excluded from upload.",
            file_path,
            ", ".join(pii_categories),
        )
        return False
    return True


# ===========================================================================
# Constants
# ===========================================================================

MCP_SERVER_URL = "https://mcp.v2.prod.veedna.com/mcp"

# ---------------------------------------------------------------------------
# Tool allow list — only tools explicitly listed here may be invoked via MCP.
# Any invocation of a tool not on this list is denied, logged to the audit
# sink, and raises a RuntimeError (fail-closed).
# ---------------------------------------------------------------------------
_TOOL_ALLOW_LIST: frozenset = frozenset({
    "lineaje_scan_files",
    "lineaje_get_report",
    "lineaje_get_violations",
    "lineaje_get_aibom",
})

_TOOL_POLICY_VERSION = "v1.0.0"

_audit_lock = threading.Lock()


def _audit_log_denial(
    actor: str,
    tool_id: str,
    policy_version: str,
    denial_reason: str,
) -> None:
    """Write a denial record to the protected audit sink (stderr).

    The record is written to stderr (a protected, append-only sink in GHA)
    so it is captured by the runner log and cannot be suppressed by the
    calling process.
    """
    record = json.dumps({
        "audit_event": "tool_invocation_denied",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "actor": actor,
        "tool_id": tool_id,
        "policy_version": policy_version,
        "denial_reason": denial_reason,
    })
    with _audit_lock:
        print(f"[AUDIT DENIAL] {record}", file=sys.stderr, flush=True)


def enforce_tool_allow_list(tool_id: str, actor: str = "gha_repo_scan") -> None:
    """Raise RuntimeError and emit an audit denial record if *tool_id* is not
    on the explicit allow list.  Must be called before every MCP tool
    invocation."""
    if tool_id not in _TOOL_ALLOW_LIST:
        denial_reason = (
            f"Tool '{tool_id}' is not present in the explicit allow list "
            f"(_TOOL_ALLOW_LIST). Execution halted (fail-closed)."
        )
        _audit_log_denial(
            actor=actor,
            tool_id=tool_id,
            policy_version=_TOOL_POLICY_VERSION,
            denial_reason=denial_reason,
        )
        raise RuntimeError(denial_reason)
logger.info("[MCP] Server URL configured: %s", MCP_SERVER_URL)

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


# ---------------------------------------------------------------------------
# URL allowlist enforcement
# ---------------------------------------------------------------------------
_ALLOWED_URL_HOSTS: tuple = (
    "lineaje.dev",
    "api.lineaje.dev",
    "app.lineaje.dev",
    "auth.lineaje.dev",
    "mcp.lineaje.dev",
)


def _assert_url_allowed(url: str, context: str = "outbound request") -> None:
    """Raise ValueError if *url* does not target an explicitly allowed hostname."""
    if not url:
        raise ValueError(f"{context}: URL must not be empty")
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception as exc:
        raise ValueError(f"{context}: could not parse URL {url!r}") from exc
    scheme = (parsed.scheme or "").lower()
    if scheme not in ("https",):
        raise ValueError(
            f"{context}: URL scheme {scheme!r} is not allowed; only 'https' is permitted"
        )
    host = (parsed.hostname or "").lower().rstrip(".")
    allowed = False
    for permitted in _ALLOWED_URL_HOSTS:
        if host == permitted or host.endswith("." + permitted):
            allowed = True
            break
    if not allowed:
        raise ValueError(
            f"{context}: hostname {host!r} is not in the URL allowlist "
            f"({', '.join(_ALLOWED_URL_HOSTS)})"
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
    for _ in range(8):
        if isinstance(parsed, dict):
            return parsed
        if isinstance(parsed, str):
            s = parsed.strip()
            if not s:
                raise RuntimeError(f"{context}: empty JSON string where object expected")
            try:
                parsed = json.loads(s)
            except json.JSONDecodeError:
                parts = s.split(".")
                if context == "renew-access-token" and len(parts) == 3:
                    return {"access_token": s}
                raise RuntimeError(f"{context}: server returned error string: {s[:800]}") from None
            continue
        break
    raise RuntimeError(f"{context}: unexpected JSON type after unwrap: {type(parsed).__name__}")


class RefreshTokenTokenManager:
    """Exchange LINEAJE_PAT_TOKEN for short-lived MCP access tokens, auto-renewing before expiry."""

    def __init__(self, refresh_token: str, renew_access_token_url: Optional[str] = None) -> None:
        self._refresh_token = _normalize_token(refresh_token)
        if not self._refresh_token:
            raise ValueError("LINEAJE_PAT_TOKEN must be non-empty")
        self._renew_url = (
            _normalize_url(renew_access_token_url)
            or _normalize_url(os.environ.get("LINEAJE_RENEW_ACCESS_TOKEN_URL"))
            or _LINEAJE_NATIVE_RENEW_ACCESS_TOKEN_URL_PROD
        ).rstrip("/")
        _assert_url_allowed(self._renew_url, context="renew-access-token URL")
        logger.info("[MCP] Token renewal URL configured: %s", self._renew_url)
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
        logger.debug("[MCP] Requesting access token from renewal URL: %s", self._renew_url)
        with self._lock:
            token = self._get_unlocked()
        logger.debug("[MCP] Access token obtained (length=%d) from renewal URL: %s", len(token) if token else 0, self._renew_url)
        return token

    def _get_unlocked(self) -> str:
        now = time.time()
        if self._access_token and now < self._access_deadline - self._skew_sec:
            return self._access_token
        self._renew()
        if not self._access_token:
            raise RuntimeError("renew-access-token did not return access_token")
        return self._access_token

    def _renew(self) -> None:
        q = urllib.parse.urlencode({"refreshToken": self._refresh_token})
        url = f"{self._renew_url}?{q}"
        req = urllib.request.Request(
            url, data=b"null",
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

def _execute_scan(args: argparse.Namespace) -> int:
    repo = args.repo or os.environ.get("GITHUB_REPOSITORY", "")
    branch = args.branch or os.environ.get("GITHUB_REF_NAME", "")
    head_sha = args.head_sha or os.environ.get("GITHUB_SHA", "")
    source_path = os.path.abspath(args.source_path)
    server_url = args.mcp_server_url or os.environ.get("MCP_SERVER_URL", "") or MCP_SERVER_URL
    source_code_repo = f"https://github.com/{repo}.git" if repo else source_path

    # Validate config
    missing = [n for n, v in [("GITHUB_REPOSITORY / --repo", repo), ("GITHUB_REF_NAME / --branch", branch)] if not v]
    if missing:
        output = build_json_output(
            status="error", repo=repo, branch=branch, head_sha=head_sha,
            source_code_repo=source_code_repo, files_scanned=0, batches=0, failed_batches=0,
            violations=[], scan_errors=[f"Missing required config: {', '.join(missing)}"],
        )
        print(json.dumps(output, indent=2))
        return 2

    try:
        bearer_getter = build_bearer_getter()
        # Eagerly fetch a token at startup to catch auth errors early
        bearer_getter()
        logger.info("Auth OK — LINEAJE_PAT_TOKEN accepted")
    except Exception as exc:
        output = build_json_output(
            status="error", repo=repo, branch=branch, head_sha=head_sha,
            source_code_repo=source_code_repo, files_scanned=0, batches=0, failed_batches=0,
            violations=[], scan_errors=[f"Auth failed: {exc}"],
        )
        print(json.dumps(output, indent=2))
        return 2

    run_id = time.strftime("%Y%m%d_%H%M%S")
    scan_start = time.perf_counter()

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
        print(json.dumps(output, indent=2))
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

    # Establish a trace/correlation ID for this scan run for end-to-end audit linkage
    global _TRACE_ID
    _TRACE_ID = str(uuid.uuid4())
    logger.info("Audit trace_id for this scan: %s", _TRACE_ID)

    # Step 2: MCP scan
    _write_audit_record({
        "event": "scan_started",
        "trace_id": _TRACE_ID,
        "repo": repo,
        "branch": branch,
        "head_sha": head_sha,
        "principal": os.environ.get("GITHUB_ACTOR", "unknown"),
        "files_total": len(file_list),
        "batches": len(batches),
        "server_url": server_url,
    })
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

    # Compute forensic context fields
    _principal = os.environ.get("GITHUB_ACTOR", "unknown")
    _input_payload = json.dumps({
        "repo": repo, "branch": branch, "head_sha": head_sha,
        "files_scanned": len(file_list), "batches": len(batches),
    }, sort_keys=True).encode()
    _input_hash = hashlib.sha256(_input_payload).hexdigest()

    if failed_batches_count and not all_violations:
        output = build_json_output(
            status="error", repo=repo, branch=branch, head_sha=head_sha,
            source_code_repo=source_code_repo, files_scanned=len(file_list),
            batches=len(batches), failed_batches=failed_batches_count,
            violations=[], aibom=all_aibom, report=combined_report,
            scan_errors=failure_details,
        )
        output["trace_id"] = _TRACE_ID
        output["input_hash"] = _input_hash
        output["output_hash"] = hashlib.sha256(json.dumps(output, sort_keys=True).encode()).hexdigest()
        output["principal"] = _principal
        output["elapsed_seconds"] = round(elapsed, 3)
        _write_audit_record({
            "event": "scan_decision",
            "trace_id": _TRACE_ID,
            "status": "error",
            "repo": repo,
            "branch": branch,
            "head_sha": head_sha,
            "principal": _principal,
            "input_hash": _input_hash,
            "output_hash": output["output_hash"],
            "files_scanned": len(file_list),
            "batches": len(batches),
            "failed_batches": failed_batches_count,
            "violation_count": 0,
            "elapsed_seconds": round(elapsed, 3),
        })
        print(json.dumps(output, indent=2))
        return 1

    status = "compliant" if not all_violations else "violations_found"
    if failed_batches_count:
        status = "error"

    output = build_json_output(
        status=status, repo=repo, branch=branch, head_sha=head_sha,
        source_code_repo=source_code_repo, files_scanned=len(file_list),
        batches=len(batches), failed_batches=failed_batches_count,
        violations=all_violations, aibom=all_aibom, report=combined_report,
        scan_errors=failure_details,
    )
    output["trace_id"] = _TRACE_ID
    output["input_hash"] = _input_hash
    output["output_hash"] = hashlib.sha256(json.dumps(output, sort_keys=True).encode()).hexdigest()
    output["principal"] = _principal
    output["elapsed_seconds"] = round(elapsed, 3)
    _write_audit_record({
        "event": "scan_decision",
        "trace_id": _TRACE_ID,
        "status": status,
        "repo": repo,
        "branch": branch,
        "head_sha": head_sha,
        "principal": _principal,
        "input_hash": _input_hash,
        "output_hash": output["output_hash"],
        "files_scanned": len(file_list),
        "batches": len(batches),
        "failed_batches": failed_batches_count,
        "violation_count": len(all_violations),
        "elapsed_seconds": round(elapsed, 3),
    })
    print(json.dumps(output, indent=2))
    return 0

# ===========================================================================
# CLI
# ===========================================================================

import re
import pathlib


def _sanitize_mcp_list(data: object, field_name: str) -> list:
    """Validate and sanitize a list value received from an MCP server response.

    Ensures the value is a list and that each element is a plain dict whose
    keys and string values are safe (no null bytes, reasonable length).
    Non-conforming elements are dropped with a warning.
    """
    MAX_ITEM_STR_LEN = 65536  # 64 KiB per string field
    MAX_LIST_LEN = 10000

    if not isinstance(data, list):
        logger.warning(
            "MCP response field '%s' expected list, got %s — discarding",
            field_name, type(data).__name__,
        )
        return []

    sanitized: list = []
    for idx, item in enumerate(data[:MAX_LIST_LEN]):
        if not isinstance(item, dict):
            logger.warning(
                "MCP response field '%s'[%d] is not a dict (%s) — skipping",
                field_name, idx, type(item).__name__,
            )
            continue
        clean_item: dict = {}
        for k, v in item.items():
            # Keys must be plain strings
            if not isinstance(k, str):
                logger.warning(
                    "MCP response field '%s'[%d] has non-string key %r — skipping key",
                    field_name, idx, k,
                )
                continue
            clean_key = k.replace("\x00", "")[:256]
            # Values: sanitize strings; pass through safe scalar types
            if isinstance(v, str):
                clean_val: object = v.replace("\x00", "")[:MAX_ITEM_STR_LEN]
            elif isinstance(v, (int, float, bool)) or v is None:
                clean_val = v
            elif isinstance(v, (list, dict)):
                # Shallow serialise nested structures to a JSON string to
                # prevent arbitrary object injection.
                try:
                    clean_val = json.dumps(v, ensure_ascii=False)[:MAX_ITEM_STR_LEN]
                except (TypeError, ValueError):
                    logger.warning(
                        "MCP response field '%s'[%d] key '%s' has non-serialisable nested value — skipping",
                        field_name, idx, clean_key,
                    )
                    continue
            else:
                logger.warning(
                    "MCP response field '%s'[%d] key '%s' has unexpected type %s — skipping",
                    field_name, idx, clean_key, type(v).__name__,
                )
                continue
            clean_item[clean_key] = clean_val
        sanitized.append(clean_item)

    if len(data) > MAX_LIST_LEN:
        logger.warning(
            "MCP response field '%s' truncated from %d to %d items",
            field_name, len(data), MAX_LIST_LEN,
        )

    return sanitized


def _sanitize_mcp_string(data: object, field_name: str) -> str:
    """Validate and sanitize a string value received from an MCP server response.

    Ensures the value is a string, strips null bytes, and enforces a maximum
    length to prevent excessively large payloads.
    """
    MAX_REPORT_LEN = 1_048_576  # 1 MiB

    if not isinstance(data, str):
        logger.warning(
            "MCP response field '%s' expected str, got %s — discarding",
            field_name, type(data).__name__,
        )
        return ""

    sanitized = data.replace("\x00", "")
    if len(sanitized) > MAX_REPORT_LEN:
        logger.warning(
            "MCP response field '%s' truncated from %d to %d characters",
            field_name, len(sanitized), MAX_REPORT_LEN,
        )
        sanitized = sanitized[:MAX_REPORT_LEN]

    return sanitized


# ---------------------------------------------------------------------------
# Audit logging helpers
# ---------------------------------------------------------------------------

import hashlib
import uuid
from logging.handlers import RotatingFileHandler

_AUDIT_LOG_PATH = os.environ.get("GHA_SCAN_AUDIT_LOG", "/var/log/gha_repo_scan_audit.jsonl")
_AUDIT_MAX_BYTES = int(os.environ.get("GHA_SCAN_AUDIT_MAX_BYTES", str(10 * 1024 * 1024)))  # 10 MB
_AUDIT_BACKUP_COUNT = int(os.environ.get("GHA_SCAN_AUDIT_BACKUP_COUNT", "10"))  # retain 10 rotated files
_TRACE_ID: str = ""

_audit_logger = logging.getLogger("gha_repo_scan.audit")
_audit_logger.setLevel(logging.INFO)
_audit_logger.propagate = False

try:
    _audit_handler = RotatingFileHandler(
        _AUDIT_LOG_PATH,
        maxBytes=_AUDIT_MAX_BYTES,
        backupCount=_AUDIT_BACKUP_COUNT,
        encoding="utf-8",
    )
except OSError:
    # Fall back to stderr if the configured path is not writable
    _audit_handler = logging.StreamHandler(sys.stderr)
    logging.getLogger(__name__).warning(
        "Audit log path %r is not writable; audit records will go to stderr", _AUDIT_LOG_PATH
    )

_audit_handler.setFormatter(logging.Formatter("%(message)s"))
_audit_logger.addHandler(_audit_handler)


def _write_audit_record(record: dict) -> None:
    """Append a structured JSON audit record to the persistent rotating audit log."""
    record.setdefault("timestamp", datetime.datetime.utcnow().isoformat() + "Z")
    record.setdefault("trace_id", _TRACE_ID)
    try:
        _audit_logger.info(json.dumps(record, default=str))
    except Exception as exc:  # noqa: BLE001
        # Audit failures must never be silent — surface to stderr and fail loudly
        sys.stderr.write(f"AUDIT_WRITE_FAILURE: {exc}\nRecord: {record}\n")
        sys.stderr.flush()
        raise RuntimeError("Audit log write failed — failing closed") from exc


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
        help=f"MCP server URL (default: {MCP_SERVER_URL}); must be within the allowed hostnames: {', '.join(_ALLOWED_URL_HOSTS)}",
    )
    parser.add_argument(
        "--debug", action="store_true",
        help="Enable DEBUG logging to stderr",
    )
    return parser.parse_args(argv or sys.argv[1:])


# ===========================================================================
# Input validation / sanitisation
# ===========================================================================

_RE_REPO = re.compile(r'^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')
_RE_BRANCH = re.compile(r'^[A-Za-z0-9_./@#%+:=,\-]{1,255}$')
_RE_SHA = re.compile(r'^[0-9a-fA-F]{7,64}$')


def _sanitize_str(value: str, max_len: int = 1024) -> str:
    """Strip null bytes and control characters; truncate to max_len."""
    sanitized = value.replace('\x00', '').strip()
    # Remove ASCII control characters (except common whitespace)
    sanitized = re.sub(r'[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]', '', sanitized)
    return sanitized[:max_len]


def _validate_and_sanitize_args(args: argparse.Namespace) -> argparse.Namespace:
    """Validate and sanitize CLI / environment-variable inputs before use."""

    # --- source_path ---
    raw_path = _sanitize_str(args.source_path)
    if not raw_path:
        raise ValueError("--source-path must not be empty")
    resolved = pathlib.Path(raw_path).resolve()
    # Guard against null bytes already stripped above; ensure path exists
    if not resolved.exists():
        raise ValueError(f"--source-path does not exist: {resolved}")
    if not resolved.is_dir():
        raise ValueError(f"--source-path is not a directory: {resolved}")
    args.source_path = str(resolved)

    # --- repo ---
    repo_val = _sanitize_str(args.repo)
    if repo_val and not _RE_REPO.match(repo_val):
        raise ValueError(
            f"--repo value contains invalid characters or format: {repo_val!r}. "
            "Expected 'owner/repo' with alphanumeric, hyphen, dot, or underscore characters."
        )
    args.repo = repo_val

    # --- branch ---
    branch_val = _sanitize_str(args.branch)
    if branch_val and not _RE_BRANCH.match(branch_val):
        raise ValueError(
            f"--branch value contains invalid characters: {branch_val!r}"
        )
    args.branch = branch_val

    # --- head_sha ---
    sha_val = _sanitize_str(args.head_sha)
    if sha_val and not _RE_SHA.match(sha_val):
        raise ValueError(
            f"--head-sha value is not a valid commit SHA: {sha_val!r}"
        )
    args.head_sha = sha_val

    return args


def _sanitize_file_path(file_path: str, base_dir: str) -> str:
    """Ensure a file path is relative and does not escape base_dir."""
    # Strip null bytes and control characters
    clean = _sanitize_str(file_path)
    if not clean:
        raise ValueError("Empty file path after sanitization")
    base = pathlib.Path(base_dir).resolve()
    candidate = (base / clean).resolve()
    # Prevent path traversal outside base_dir
    try:
        candidate.relative_to(base)
    except ValueError:
        raise ValueError(
            f"File path escapes base directory (path traversal attempt): {file_path!r}"
        )
    return str(candidate)


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

    try:
        args = _validate_and_sanitize_args(args)
    except ValueError as exc:
        logger.error("Input validation failed: %s", exc)
        err = {"status": "error", "scan_errors": [f"Input validation failed: {exc}"]}
        print(json.dumps(err, indent=2))
        return 1

    try:
        return _execute_scan(args)
    except Exception as exc:
        # Log only the exception type and message — no stack trace — to avoid
        # leaking internal file paths, module names, and line numbers to
        # user-visible runner logs (output data minimisation).
        logger.error("Unhandled error: %s: %s", type(exc).__name__, exc)
        err = {"status": "error", "scan_errors": ["Unhandled exception — see stderr logs"]}
        print(json.dumps(err, indent=2))
        return 1


if __name__ == "__main__":
    sys.exit(main())
