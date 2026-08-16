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
import ssl
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("gha_repo_scan")

# ===========================================================================
# Constants
# ===========================================================================

MCP_SERVER_URL = "https://mcp.v2.prod.veedna.com/mcp"

# Explicit allow list of MCP tool names that agents are permitted to invoke.
# Any tool NOT in this set will be rejected before execution.
ALLOWED_TOOLS: frozenset = frozenset({
    "scan_files",
    "get_policy_report",
    "list_violations",
    "get_aibom",
    "read_file",
    "list_files",
})


def _assert_tool_allowed(tool_name: str) -> None:
    """Raise ValueError if *tool_name* is not in the explicit allow list.

    This must be called before every MCP tool invocation so that the
    FileManagementAgent and any other MCP client code cannot execute
    tools that have not been explicitly approved.
    """
    if tool_name not in ALLOWED_TOOLS:
        raise ValueError(
            f"Tool '{tool_name}' is not in the MCP tool allow list. "
            f"Permitted tools: {sorted(ALLOWED_TOOLS)}"
        )
MCP_SERVER_HOSTNAME = "mcp.v2.prod.veedna.com"


def _create_mcp_ssl_context() -> ssl.SSLContext:
    """Return an SSLContext that verifies the MCP server certificate and hostname."""
    ctx = ssl.create_default_context()
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = True
    return ctx


_MCP_SSL_CONTEXT: ssl.SSLContext = _create_mcp_ssl_context()

# ---------------------------------------------------------------------------
# Input sanitization for AI model submissions
# ---------------------------------------------------------------------------

_MAX_FILE_CONTENT_BYTES = 512_000  # 512 KB per file
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _sanitize_file_content(content: str, path: str = "") -> Optional[str]:
    """Sanitize and validate file content before sending to the AI model.

    Steps:
    1. Ensure the value is a plain ``str``; reject anything else.
    2. Enforce a maximum byte length (``_MAX_FILE_CONTENT_BYTES``).
    3. Strip null bytes and non-printable ASCII control characters
       (keeps \t, \n, \r which are legitimate in source code).
    4. Verify the result round-trips through UTF-8 without errors.

    Returns the sanitized string, or ``None`` if the content should be
    skipped entirely (e.g. binary-looking data that fails UTF-8 validation).
    """
    if not isinstance(content, str):
        logger.warning("Skipping non-string content for path %r", path)
        return None

    # Enforce size limit — truncate rather than drop so partial analysis is
    # still possible, but log a warning so the caller is aware.
    encoded = content.encode("utf-8", errors="replace")
    if len(encoded) > _MAX_FILE_CONTENT_BYTES:
        logger.warning(
            "File %r exceeds max content size (%d bytes); truncating to %d bytes.",
            path,
            len(encoded),
            _MAX_FILE_CONTENT_BYTES,
        )
        encoded = encoded[:_MAX_FILE_CONTENT_BYTES]
        content = encoded.decode("utf-8", errors="replace")

    # Strip null bytes and dangerous control characters.
    content = _CONTROL_CHAR_RE.sub("", content)

    # Final UTF-8 round-trip validation.
    try:
        content.encode("utf-8").decode("utf-8")
    except (UnicodeEncodeError, UnicodeDecodeError) as exc:
        logger.warning("File %r failed UTF-8 validation after sanitization: %s", path, exc)
        return None

    return content

# Maximum allowed size for MCP server responses (10 MB)
_MCP_MAX_RESPONSE_SIZE = 10 * 1024 * 1024
# Allowed top-level keys in a valid MCP response
_MCP_ALLOWED_RESPONSE_KEYS = frozenset({"jsonrpc", "id", "result", "error"})


def sanitize_mcp_response(raw: Any) -> Any:
    """Validate and sanitize output received from the MCP server.

    Raises ``ValueError`` if the response fails structural validation so that
    callers never operate on untrusted / malformed data.

    Parameters
    ----------
    raw:
        The parsed (JSON-decoded) response object returned by the MCP server.

    Returns
    -------
    Any
        The sanitized response (a plain ``dict`` / ``list`` / scalar with all
        string values stripped of leading/trailing whitespace and NUL bytes).
    """
    # --- size guard (applied to the serialised form) -----------------------
    try:
        serialised = json.dumps(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"MCP response is not JSON-serialisable: {exc}") from exc

    if len(serialised) > _MCP_MAX_RESPONSE_SIZE:
        raise ValueError(
            f"MCP response exceeds maximum allowed size "
            f"({len(serialised)} > {_MCP_MAX_RESPONSE_SIZE} bytes)"
        )

    # --- structural validation ---------------------------------------------
    if not isinstance(raw, dict):
        raise ValueError(
            f"MCP response must be a JSON object, got {type(raw).__name__!r}"
        )

    unexpected = set(raw.keys()) - _MCP_ALLOWED_RESPONSE_KEYS
    if unexpected:
        raise ValueError(
            f"MCP response contains unexpected top-level keys: {sorted(unexpected)}"
        )

    if "jsonrpc" in raw and raw["jsonrpc"] != "2.0":
        raise ValueError(
            f"MCP response has unexpected jsonrpc version: {raw['jsonrpc']!r}"
        )

    if "error" in raw and "result" in raw:
        raise ValueError(
            "MCP response contains both 'error' and 'result' fields — "
            "this is not a valid JSON-RPC 2.0 response"
        )

    # --- recursive sanitisation of string values ---------------------------
    def _sanitize(obj: Any) -> Any:  # noqa: ANN001
        if isinstance(obj, str):
            # Strip NUL bytes and leading/trailing whitespace
            return obj.replace("\x00", "").strip()
        if isinstance(obj, dict):
            return {_sanitize(k): _sanitize(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [_sanitize(item) for item in obj]
        # int, float, bool, None — pass through unchanged
        return obj

    return _sanitize(raw)


def _log_mcp_request(method: str, url: str, payload: Any) -> None:
    """Log an outgoing MCP server request."""
    try:
        payload_summary = json.dumps(payload)[:500] if payload is not None else "<none>"
    except Exception:
        payload_summary = "<unserializable>"
    logger.info(
        "MCP request: method=%s url=%s payload_summary=%s",
        method,
        url,
        payload_summary,
    )


def _log_mcp_response(url: str, status_code: int, response_body: Any) -> None:
    """Log an incoming MCP server response."""
    try:
        body_summary = json.dumps(response_body)[:500] if response_body is not None else "<none>"
    except Exception:
        body_summary = "<unserializable>"
    logger.info(
        "MCP response: url=%s status=%s body_summary=%s",
        url,
        status_code,
        body_summary,
    )

MAX_SCAN_WORKERS = 4
DEFAULT_UNIFAI_FILE_BATCH_SIZE = 100

# ===========================================================================
# Prompt-injection sanitization
# ===========================================================================

# Invisible / zero-width Unicode characters often used to hide injected text
_INVISIBLE_CHARS_RE = re.compile(
    r"[\u00ad\u200b-\u200f\u202a-\u202e\u2060-\u2064\u206a-\u206f\ufeff\u2028\u2029]"
)

# Patterns that look like shell commands embedded in prose
_SHELL_CMD_RE = re.compile(
    r"(?:^|\s)(?:sudo|bash|sh|zsh|fish|cmd\.exe|powershell|pwsh|curl|wget|nc|ncat|netcat"
    r"|chmod|chown|rm\s+-rf|mkfifo|eval|exec|system|popen|subprocess)\b",
    re.IGNORECASE | re.MULTILINE,
)

# Looks like a base64 blob (≥ 40 contiguous base64 chars)
_BASE64_BLOB_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")

# Common leetspeak substitution map (used to obfuscate keywords)
_LEET_TABLE = str.maketrans("013456789", "oieassbtg")

_DANGEROUS_KEYWORDS = frozenset({
    "ignore previous instructions",
    "disregard all prior",
    "you are now",
    "act as",
    "jailbreak",
    "do anything now",
    "dan mode",
    "override policy",
    "forget your instructions",
    "new instructions",
    "system prompt",
    "<system>",
    "[system]",
    "###instruction",
    "###system",
})


def _contains_dangerous_keyword(text: str) -> bool:
    """Return True if *text* (or its leet-decoded form) contains a dangerous keyword."""
    lower = text.lower()
    leet_decoded = lower.translate(_LEET_TABLE)
    for kw in _DANGEROUS_KEYWORDS:
        if kw in lower or kw in leet_decoded:
            return True
    return False


def _looks_like_base64_command(blob: str) -> bool:
    """Return True if a base64 blob decodes to something that looks like a shell command."""
    try:
        decoded = base64.b64decode(blob + "==").decode("utf-8", errors="replace")
        if _SHELL_CMD_RE.search(decoded):
            return True
        if _contains_dangerous_keyword(decoded):
            return True
    except Exception:  # noqa: BLE001
        pass
    return False


def sanitize_file_content_for_prompt(path: str, content: str) -> Tuple[bool, str]:
    """Validate *content* before it is forwarded to the AI agent as a prompt.

    Returns ``(safe, reason)`` where *safe* is ``True`` when the content passes
    all checks and *reason* is an empty string.  When *safe* is ``False``,
    *reason* describes the first detected issue.

    Checks performed
    ----------------
    1. Binary / non-UTF-8 content (executable bytes).
    2. Invisible / zero-width Unicode characters (hidden prompt injection).
    3. Dangerous natural-language keywords (prompt-override attempts).
    4. Leetspeak-obfuscated dangerous keywords.
    5. Base64 blobs that decode to shell commands or dangerous keywords.
    6. Bare shell commands embedded in the text.
    """
    # 1. Reject content that cannot be cleanly decoded as text
    if "\x00" in content:
        return False, f"{path}: contains null bytes (possible binary/executable content)"

    # 2. Invisible characters
    if _INVISIBLE_CHARS_RE.search(content):
        return False, f"{path}: contains invisible/zero-width Unicode characters"

    # 3 & 4. Dangerous keywords (plain + leet)
    if _contains_dangerous_keyword(content):
        return False, f"{path}: contains prompt-injection keyword"

    # 5. Base64 blobs
    for match in _BASE64_BLOB_RE.finditer(content):
        if _looks_like_base64_command(match.group()):
            return False, f"{path}: contains base64-encoded shell command or injection keyword"

    # 6. Shell commands
    if _SHELL_CMD_RE.search(content):
        # Only flag when the shell token appears outside of obvious code contexts
        # (i.e. not inside a string literal or comment) — we do a lightweight
        # heuristic: if the file extension is a known source-code type we allow
        # it, otherwise we block it.
        _CODE_EXTENSIONS = {
            ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb",
            ".rs", ".c", ".cpp", ".h", ".cs", ".php", ".sh", ".bash",
            ".zsh", ".fish", ".ps1", ".bat", ".cmd", ".yaml", ".yml",
            ".toml", ".json", ".md", ".rst", ".txt", ".dockerfile",
            ".makefile", ".mk",
        }
        ext = pathlib.Path(path).suffix.lower()
        if ext not in _CODE_EXTENSIONS:
            return False, f"{path}: contains embedded shell command in non-code file"

    return True, ""

# ===========================================================================
# Prompt-injection sanitisation
# ===========================================================================

# Patterns that indicate an attempt to inject instructions into file content.
_PROMPT_INJECTION_PATTERNS: list[re.Pattern] = [
    # Direct role/instruction overrides
    re.compile(
        r"(ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context))",
        re.IGNORECASE,
    ),
    re.compile(
        r"(you\s+are\s+now|act\s+as|pretend\s+(to\s+be|you\s+are)|roleplay\s+as|your\s+new\s+(role|persona|instructions?)\s+are)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(system\s*:\s*|<\s*system\s*>|\[\s*system\s*\]|###\s*system)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(assistant\s*:\s*|<\s*assistant\s*>|\[\s*assistant\s*\])",
        re.IGNORECASE,
    ),
    # Shell command injection
    re.compile(
        r"(\$\(|`[^`]+`|\beval\s*\(|\bexec\s*\(|\bos\.system\s*\(|\bsubprocess\.)",
        re.IGNORECASE,
    ),
    # Base64-encoded blobs that could hide instructions (>40 contiguous base64 chars)
    re.compile(r"[A-Za-z0-9+/]{40,}={0,2}"),
    # Leetspeak / obfuscated "ignore" variants
    re.compile(r"[i1][g9][n][o0][r3][e3]", re.IGNORECASE),
    # Null-byte / zero-width character injection
    re.compile(r"[\x00\u200b\u200c\u200d\ufeff]"),
    # Prompt-delimiter smuggling
    re.compile(r"(<<<|>>>|\[INST\]|\[/INST\]|<\|im_start\||<\|im_end\||<\|endoftext\|>)"),
    # Data-exfiltration / SSRF hints inside file content
    re.compile(
        r"(exfiltrate|send\s+(all|the)\s+(data|contents?|files?)|http[s]?://(?!localhost)[^\s]{0,200})",
        re.IGNORECASE,
    ),
]

_MAX_SAFE_FILE_BYTES = 512 * 1024  # 512 KB — truncate anything larger


def _sanitize_file_content(content: str, file_path: str = "") -> str:
    """Return a sanitised version of *content* safe to forward to the AI service.

    Steps
    -----
    1. Truncate oversized content to ``_MAX_SAFE_FILE_BYTES`` characters.
    2. Strip null bytes and zero-width characters.
    3. Scan for known prompt-injection patterns; if any are found the entire
       content is replaced with a safe placeholder so that the AI service
       receives no attacker-controlled text.

    The function never raises — on any unexpected error it returns the
    placeholder so that the scan can continue safely.
    """
    try:
        # 1. Truncate
        if len(content) > _MAX_SAFE_FILE_BYTES:
            logger.warning(
                "File '%s' truncated from %d to %d bytes before AI submission.",
                file_path,
                len(content),
                _MAX_SAFE_FILE_BYTES,
            )
            content = content[:_MAX_SAFE_FILE_BYTES]

        # 2. Strip null / zero-width chars
        content = re.sub(r"[\x00\u200b\u200c\u200d\ufeff]", "", content)

        # 3. Check for prompt-injection patterns
        for pattern in _PROMPT_INJECTION_PATTERNS:
            if pattern.search(content):
                logger.warning(
                    "Potential prompt injection detected in '%s' (pattern: %s); "
                    "file content replaced with safe placeholder.",
                    file_path,
                    pattern.pattern[:60],
                )
                return (
                    f"[CONTENT REDACTED — potential prompt injection detected in {file_path!r}]"
                )

        return content
    except Exception as exc:  # pragma: no cover
        logger.error("_sanitize_file_content error for '%s': %s", file_path, exc)
        return f"[CONTENT REDACTED — sanitisation error for {file_path!r}]"

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

    if failed_batches_count and not all_violations:
        output = build_json_output(
            status="error", repo=repo, branch=branch, head_sha=head_sha,
            source_code_repo=source_code_repo, files_scanned=len(file_list),
            batches=len(batches), failed_batches=failed_batches_count,
            violations=[], aibom=all_aibom, report=combined_report,
            scan_errors=failure_details,
        )
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
    print(json.dumps(output, indent=2))
    return 0

# ===========================================================================
# CLI
# ===========================================================================

# ===========================================================================
# Audit / forensic-readiness helpers
# ===========================================================================

import hashlib as _hashlib
import pathlib as _pathlib

_AUDIT_LOG_PATH = _pathlib.Path(os.environ.get("AI_AUDIT_LOG", "/tmp/ai_policy_audit.jsonl"))


def _write_audit_record(
    *,
    event: str,
    principal: str,
    model_id: str,
    model_version: str,
    input_hash: str,
    output: object,
    status: str,
    extra: Optional[dict] = None,
) -> None:
    """Append a single-line JSON audit record to the persistent audit log.

    Fields satisfy forensic-readiness requirements:
    timestamp, principal, model_id, model_version, input_hash, output, status.
    """
    record = {
        "timestamp": datetime.datetime.utcnow().isoformat(timespec="microseconds") + "Z",
        "event": event,
        "principal": principal,
        "model_id": model_id,
        "model_version": model_version,
        "input_hash": input_hash,
        "output": output,
        "status": status,
    }
    if extra:
        record.update(extra)
    try:
        _AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with _AUDIT_LOG_PATH.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, default=str) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
    except OSError as oe:
        # Must NOT silently swallow — re-raise after logging so callers are aware
        logger.error("AUDIT LOG WRITE FAILURE — forensic record lost: %s | record=%s", oe, record)
        raise RuntimeError(f"Audit log write failed: {oe}") from oe


def _hash_input(data: object) -> str:
    """Return a SHA-256 hex digest of the canonical JSON representation of *data*."""
    canonical = json.dumps(data, sort_keys=True, default=str).encode()
    return _hashlib.sha256(canonical).hexdigest()


def _resolve_principal(args: argparse.Namespace) -> str:
    """Return a best-effort principal identifier from env / args."""
    return (
        os.environ.get("GITHUB_ACTOR")
        or os.environ.get("GITHUB_REPOSITORY")
        or getattr(args, "repo", None)
        or "unknown"
    )


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
        help=f"MCP server URL (default: {MCP_SERVER_URL})",
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

    try:
        return _execute_scan(args)
    except Exception as exc:  # noqa: BLE001
        import traceback
        tb_str = traceback.format_exc()
        logger.exception("Unhandled error")
        # --- Audit record for unhandled failure (forensic readiness) ---
        _write_audit_record(
            event="scan_unhandled_exception",
            principal=_resolve_principal(args),
            model_id="n/a",
            model_version="n/a",
            input_hash="n/a",
            output={"exception_type": type(exc).__name__, "traceback": tb_str},
            status="error",
        )
        err = {
            "status": "error",
            "scan_errors": [
                f"Unhandled exception: {type(exc).__name__}: {exc}",
                "Full traceback written to audit log and stderr.",
            ],
        }
        print(json.dumps(err, indent=2))
        return 1


if __name__ == "__main__":
    sys.exit(main())
