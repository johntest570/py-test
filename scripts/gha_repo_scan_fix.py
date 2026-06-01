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
# LLM Output Sanitization
# ===========================================================================

# Patterns that indicate dynamic code execution primitives in LLM output
_DANGEROUS_PATTERNS: List[Tuple[str, str]] = [
    (r'\beval\s*\(', 'eval()'),
    (r'\bexec\s*\(', 'exec()'),
    (r'\bcompile\s*\(', 'compile()'),
    (r'\b__import__\s*\(', '__import__()'),
    (r'\bimportlib\.import_module\s*\(', 'importlib.import_module()'),
    (r'\bos\.system\s*\(', 'os.system()'),
    (r'\bos\.popen\s*\(', 'os.popen()'),
    (r'\bsubprocess\.(?:call|run|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True',
     'subprocess(...shell=True)'),
    (r'\bpickle\.loads?\s*\(', 'pickle.load(s)()'),
    (r'\bmarshal\.loads?\s*\(', 'marshal.load(s)()'),
    (r'\bctypes\.', 'ctypes usage'),
    (r'\b__builtins__\b', '__builtins__ access'),
    (r'\bgetattr\s*\(.*,\s*[\'"]__', 'getattr with dunder'),
    (r'\bsetattr\s*\(', 'setattr()'),
    (r'\bdelattr\s*\(', 'delattr()'),
    (r'\bglobals\s*\(\s*\)', 'globals()'),
    (r'\blocals\s*\(\s*\)', 'locals()'),
    (r'\bvars\s*\(\s*\)', 'vars()'),
]


def _find_dangerous_patterns(text: str) -> List[str]:
    """Return a list of dangerous pattern names found in *text*."""
    found: List[str] = []
    for pattern, label in _DANGEROUS_PATTERNS:
        if re.search(pattern, text):
            found.append(label)
    return found


def _sanitize_string(value: str, context: str = "") -> str:
    """Validate a string from LLM output for dangerous primitives.

    If dangerous patterns are detected the content is returned unchanged but
    a WARNING is emitted so that downstream consumers (CI logs, SIEM) can
    act on it.  We intentionally do *not* silently drop content so that
    legitimate security-research output (e.g. a report that *mentions* eval)
    is still surfaced — the warning is the control.
    """
    hits = _find_dangerous_patterns(value)
    if hits:
        logger.warning(
            "[LLM-OUTPUT-SANITIZE] Potentially dangerous primitive(s) detected "
            "in LLM output%s: %s",
            f" ({context})" if context else "",
            ", ".join(hits),
        )
    return value


def _sanitize_llm_value(value: Any, context: str = "") -> Any:
    """Recursively validate LLM output (dict / list / str) for dangerous primitives."""
    if isinstance(value, str):
        return _sanitize_string(value, context)
    if isinstance(value, dict):
        return {
            k: _sanitize_llm_value(v, context=f"{context}.{k}" if context else k)
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [
            _sanitize_llm_value(item, context=f"{context}[{i}]")
            for i, item in enumerate(value)
        ]
    return value


def sanitize_llm_response(response: Dict[str, Any]) -> Dict[str, Any]:
    """Validate and sanitize all LLM-originated fields in a scan response.

    Fields checked: ``violations``, ``fix_code``, ``aibom``, ``report``.
    Returns the (possibly annotated) response dict.
    """
    for field in ("violations", "fix_code", "aibom", "report"):
        if field in response:
            response[field] = _sanitize_llm_value(response[field], context=field)
    return response

# ===========================================================================
# Constants
# ===========================================================================

MCP_SERVER_URL = "https://mcp.v2.prod.veedna.com/mcp"  # TLS-only endpoint; sessions use signed tokens

# ===========================================================================
# Prompt Sanitization
# ===========================================================================

# Invisible/hidden Unicode characters that may be used to smuggle instructions
_INVISIBLE_CHAR_PATTERN = re.compile(
    r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f"
    r"\u00ad\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff\ufff9-\ufffb]"
)

# Shell command patterns that should not appear in prompt content
_SHELL_COMMAND_PATTERN = re.compile(
    r"(?:^|\s|;|&&|\|\|)"
    r"(?:bash|sh|zsh|ksh|csh|cmd\.exe|powershell|pwsh|eval|exec|system|popen)"
    r"\s*(?:-[a-zA-Z]+\s+)?[\"']?(?:/[^\s]*|[a-zA-Z]:\\[^\s]*|`[^`]+`|\$\([^)]+\))",
    re.IGNORECASE | re.MULTILINE,
)

# Binary executable magic bytes (ELF, PE/MZ, Mach-O, shebang with interpreter)
_BINARY_MAGIC: list[bytes] = [
    b"\x7fELF",          # ELF executable (Linux)
    b"MZ",              # PE/MZ executable (Windows)
    b"\xfe\xed\xfa\xce", # Mach-O 32-bit
    b"\xfe\xed\xfa\xcf", # Mach-O 64-bit
    b"\xce\xfa\xed\xfe", # Mach-O 32-bit (reversed)
    b"\xcf\xfa\xed\xfe", # Mach-O 64-bit (reversed)
    b"\xca\xfe\xba\xbe", # Mach-O fat binary
]


def _is_base64_encoded_command(text: str) -> bool:
    """Return True if *text* contains a base64 string that decodes to a shell command."""
    # Match standalone base64-looking tokens (min 20 chars to reduce false positives)
    b64_pattern = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
    shell_indicators = (
        b"bash", b"sh ", b"/bin/", b"eval", b"exec",
        b"wget", b"curl", b"chmod", b"python", b"perl", b"ruby",
        b"powershell", b"cmd.exe", b"system(", b"popen(",
    )
    for match in b64_pattern.finditer(text):
        token = match.group(0)
        # Pad to valid base64 length
        padding = (4 - len(token) % 4) % 4
        try:
            decoded = base64.b64decode(token + "=" * padding)
            decoded_lower = decoded.lower()
            if any(indicator in decoded_lower for indicator in shell_indicators):
                return True
        except Exception:
            continue
    return False


def _has_binary_executable_signature(content_bytes: bytes) -> bool:
    """Return True if *content_bytes* starts with a known binary executable magic number."""
    for magic in _BINARY_MAGIC:
        if content_bytes.startswith(magic):
            return True
    return False


def sanitize_prompt_content(file_path: str, content: str) -> str:
    """Validate and sanitize file content before use as an AI prompt.

    Raises ``ValueError`` if the content contains patterns that could be used
    to inject malicious commands into the AI agent at runtime.

    Returns the original *content* unchanged when no violations are detected.
    """
    # 1. Check for binary executable signatures
    try:
        raw_bytes = content.encode("utf-8", errors="replace")
    except Exception:
        raw_bytes = b""
    if _has_binary_executable_signature(raw_bytes):
        raise ValueError(
            f"Prompt sanitization rejected '{file_path}': "
            "content begins with a binary executable signature."
        )

    # 2. Check for hidden/invisible Unicode characters
    if _INVISIBLE_CHAR_PATTERN.search(content):
        raise ValueError(
            f"Prompt sanitization rejected '{file_path}': "
            "content contains hidden or invisible Unicode characters that may smuggle instructions."
        )

    # 3. Check for base64-encoded shell commands
    if _is_base64_encoded_command(content):
        raise ValueError(
            f"Prompt sanitization rejected '{file_path}': "
            "content contains base64-encoded data that decodes to shell commands."
        )

    # 4. Check for direct shell command injection patterns
    if _SHELL_COMMAND_PATTERN.search(content):
        raise ValueError(
            f"Prompt sanitization rejected '{file_path}': "
            "content contains shell command patterns that could execute malicious instructions."
        )

    return content

# ===========================================================================
# Input Sanitization
# ===========================================================================

_MAX_FILE_CONTENT_BYTES = 512 * 1024  # 512 KB per file
_SECRET_PATTERNS = [
    re.compile(r'(?i)(api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token|password|passwd|private[_-]?key)\s*[:=]\s*[\'"]?([A-Za-z0-9+/=_\-]{8,})[\'"]?'),
    re.compile(r'(?i)(bearer\s+)([A-Za-z0-9\-._~+/]+=*)'),
    re.compile(r'(?i)(ghp_|ghs_|github_pat_)[A-Za-z0-9_]{10,}'),
    re.compile(r'(?i)(sk-|pk-)[A-Za-z0-9]{20,}'),
]


def sanitize_file_content(content: str, file_path: str = "") -> Optional[str]:
    """Sanitize and validate file content before sending to the MCP/LLM endpoint.

    Returns sanitized content string, or None if the content should be skipped.
    """
    # Validate and enforce UTF-8 encoding
    if isinstance(content, bytes):
        try:
            content = content.decode("utf-8", errors="strict")
        except (UnicodeDecodeError, ValueError):
            logger.warning("Skipping file %s: content is not valid UTF-8", file_path)
            return None

    if not isinstance(content, str):
        logger.warning("Skipping file %s: content is not a string", file_path)
        return None

    # Enforce maximum content size
    encoded = content.encode("utf-8", errors="replace")
    if len(encoded) > _MAX_FILE_CONTENT_BYTES:
        logger.warning(
            "Truncating file %s: content exceeds %d bytes (actual: %d bytes)",
            file_path, _MAX_FILE_CONTENT_BYTES, len(encoded),
        )
        content = encoded[:_MAX_FILE_CONTENT_BYTES].decode("utf-8", errors="replace")

    # Strip null bytes
    content = content.replace("\x00", "")

    # Strip non-printable control characters (keep newlines, tabs, carriage returns)
    content = re.sub(r'[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]', '', content)

    # Redact secret-like patterns to avoid leaking credentials to the LLM
    for pattern in _SECRET_PATTERNS:
        content = pattern.sub(lambda m: m.group(0)[:m.start(2) - m.start(0)] + '[REDACTED]', content)

    return content


def sanitize_mcp_output(data: Any, max_depth: int = 10, _depth: int = 0) -> Any:
    """Validate and sanitize output received from the MCP server.

    Applies the following controls:
    - Enforces a maximum recursion depth to prevent deeply nested payloads.
    - Strips NUL bytes and control characters from string values.
    - Limits individual string length to 1 MB to prevent memory exhaustion.
    - Rejects unexpected top-level types (only dict, list, str, int, float,
      bool, and None are accepted).
    - Removes keys whose names contain characters outside [A-Za-z0-9_.\-].

    Args:
        data: Raw value returned by an MCP tool call.
        max_depth: Maximum allowed nesting depth (default 10).
        _depth: Internal recursion counter — callers should not set this.

    Returns:
        A sanitized copy of *data* safe for further processing.

    Raises:
        ValueError: If *data* contains a type that is not permitted.
    """
    _MAX_STRING_LEN = 1_048_576  # 1 MiB
    _SAFE_KEY_RE = re.compile(r'^[A-Za-z0-9_.\-]+$')

    if _depth > max_depth:
        logger.warning("sanitize_mcp_output: max nesting depth %d exceeded; truncating", max_depth)
        return None

    if data is None or isinstance(data, (bool, int, float)):
        return data

    if isinstance(data, str):
        # Remove NUL bytes and ASCII control characters (except tab/newline/CR)
        sanitized = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', data)
        if len(sanitized) > _MAX_STRING_LEN:
            logger.warning(
                "sanitize_mcp_output: string value truncated from %d to %d bytes",
                len(sanitized), _MAX_STRING_LEN,
            )
            sanitized = sanitized[:_MAX_STRING_LEN]
        return sanitized

    if isinstance(data, list):
        return [
            sanitize_mcp_output(item, max_depth=max_depth, _depth=_depth + 1)
            for item in data
        ]

    if isinstance(data, dict):
        result: Dict[str, Any] = {}
        for key, value in data.items():
            if not isinstance(key, str):
                logger.warning("sanitize_mcp_output: dropping non-string key %r", key)
                continue
            if not _SAFE_KEY_RE.match(key):
                logger.warning("sanitize_mcp_output: dropping unsafe key %r", key)
                continue
            result[key] = sanitize_mcp_output(value, max_depth=max_depth, _depth=_depth + 1)
        return result

    raise ValueError(
        f"sanitize_mcp_output: unexpected type {type(data).__name__!r} in MCP server response"
    )


def _mcp_request(method: str, url: str, payload: Any = None, headers: Optional[Dict[str, str]] = None, timeout: int = 60) -> Any:
    """Send a request to the MCP server with mandatory interaction logging.

    All MCP client interactions MUST be logged (request and response) per
    security policy. This function is the single authorised entry-point for
    every call to MCP_SERVER_URL.
    """
    sanitized_payload = None
    if payload is not None:
        try:
            raw = json.dumps(payload)
            sanitized_payload = raw[:500] + ("…" if len(raw) > 500 else "")
        except Exception:
            sanitized_payload = "<non-serialisable payload>"

    logger.info(
        "[MCP REQUEST] method=%s url=%s payload_preview=%s",
        method.upper(),
        url,
        sanitized_payload,
    )

    body_bytes = json.dumps(payload).encode() if payload is not None else None
    req_headers = {"Content-Type": "application/json", **(headers or {})}
    req = urllib.request.Request(url, data=body_bytes, headers=req_headers, method=method.upper())

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status_code = resp.status
            raw_body = resp.read()
            try:
                response_obj = json.loads(raw_body)
            except Exception:
                response_obj = raw_body.decode(errors="replace")

            preview = ""
            try:
                preview_str = json.dumps(response_obj)
                preview = preview_str[:500] + ("…" if len(preview_str) > 500 else "")
            except Exception:
                preview = str(response_obj)[:500]

            logger.info(
                "[MCP RESPONSE] method=%s url=%s status=%s response_preview=%s",
                method.upper(),
                url,
                status_code,
                preview,
            )
            return response_obj
    except urllib.error.HTTPError as exc:
        error_body = ""
        try:
            error_body = exc.read().decode(errors="replace")[:500]
        except Exception:
            pass
        logger.error(
            "[MCP RESPONSE ERROR] method=%s url=%s status=%s error_body=%s",
            method.upper(),
            url,
            exc.code,
            error_body,
        )
        raise
    except Exception as exc:
        logger.error(
            "[MCP RESPONSE ERROR] method=%s url=%s error=%s",
            method.upper(),
            url,
            exc,
        )
        raise

MAX_SCAN_WORKERS = 4
REMEDIATION_BRANCH_PREFIX = "remediation/unifai-gha"
DEFAULT_UNIFAI_FILE_BATCH_SIZE = 100


def _sanitize_batch_files(files: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Sanitize all file content entries in a batch before submission to MCP."""
    sanitized = []
    for entry in files:
        raw_content = entry.get("content", "")
        clean_content = sanitize_file_content(raw_content, file_path=entry.get("path", ""))
        if clean_content is None:
            logger.info("Excluding file from batch due to sanitization failure: %s", entry.get("path", ""))
            continue
        sanitized_entry = dict(entry)
        sanitized_entry["content"] = clean_content
        sanitized.append(sanitized_entry)
    return sanitized

_DEFAULT_LINEAJE_TOKEN_REFRESH_SKEW_SEC = 120
_SESSION_SUBJECT_PREFIX = "gha-scan"  # subject bound to session tokens
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
    remediation_pr: Optional[int] = None,
    remediation_branch: str = "",
    failed_remediation_files: Optional[List[str]] = None,
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
        "remediation_pr": remediation_pr,
        "remediation_branch": remediation_branch,
        "failed_remediation_files": failed_remediation_files or [],
        "scan_errors": scan_errors or [],
    }


def print_human_output(output: Dict[str, Any]) -> None:
    status = output.get("status", "unknown")
    violations = output.get("violations", [])
    scan_errors = output.get("scan_errors", [])
    metadata = output.get("scan_metadata", {})
    scanned_at = metadata.get("scanned_at", "")
    branch = metadata.get("branch", "")

    if status == "compliant":
        status_label = "✅ Compliant"
    elif status == "violations_found":
        status_label = "❌ Not Compliant"
    else:
        status_label = status

    print("# UnifAI Security Report")
    print()
    print(f"**Status:** {status_label}")
    if branch:
        print(f"**Branch:** `{branch}`")
    if scanned_at:
        print(f"**Scanned at:** {scanned_at}")

    if scan_errors:
        print("\n**Errors:**")
        for err in scan_errors:
            print(f"- {err}")
        print()

    if not violations:
        if status == "compliant":
            print("\nNo violations found.")
        return

    from collections import defaultdict
    by_file: Dict[str, List[str]] = defaultdict(list)
    for v in violations:
        file_ = v.get("file", "(unknown)")
        control = v.get("control", "(unknown)")
        by_file[file_].append(control)

    num_files = len(by_file)
    print(f"\n**{len(violations)} violation(s) across {num_files} file(s)**\n")

    print("| File | Policy Violations |")
    print("|------|-------------------|")

    for file_, controls in sorted(by_file.items()):
        numbered = "".join(f"{i}. {c}<br>" for i, c in enumerate(controls, 1))
        print(f"| `{file_}` | {numbered} |")


# ===========================================================================
# Patch application (ported from veracode_repo_scan.py, no external deps)
# ===========================================================================

def _normalize_for_patch_match(s: str) -> str:
    return re.sub(r"[ \t]+", " ", s)


def _apply_fix_entry(content: str, original: str, replacement: str) -> Tuple[str, bool]:
    if not original:
        return content, False

    if original in content:
        return content.replace(original, replacement, 1), True

    orig_stripped = original.strip()
    if orig_stripped and orig_stripped in content:
        return content.replace(orig_stripped, replacement, 1), True

    norm_orig = _normalize_for_patch_match(orig_stripped)
    norm_content = _normalize_for_patch_match(content)
    idx = norm_content.find(norm_orig)
    if idx != -1:
        orig_len = len(orig_stripped)
        real_idx = 0
        norm_walked = 0
        for ci, ch in enumerate(content):
            if norm_walked >= idx:
                real_idx = ci
                break
            norm_walked += len(_normalize_for_patch_match(ch))
        else:
            real_idx = len(content)
        sub = content[real_idx : real_idx + orig_len + 50]
        if orig_stripped in sub:
            actual_idx = content.find(orig_stripped, real_idx)
            if actual_idx != -1:
                return content[:actual_idx] + replacement + content[actual_idx + len(orig_stripped):], True

    orig_lines = [l for l in orig_stripped.splitlines() if l.strip()]
    if orig_lines:
        anchor = orig_lines[0].strip()
        if len(anchor) > 15:
            anchor_idx = content.find(anchor)
            if anchor_idx != -1:
                end_search = content.find(orig_lines[-1].strip(), anchor_idx) if len(orig_lines) > 1 else anchor_idx
                if end_search != -1:
                    end_idx = end_search + len(orig_lines[-1].strip())
                    found_block = content[anchor_idx:end_idx]
                    if len(found_block) < len(orig_stripped) * 2:
                        return content[:anchor_idx] + replacement + content[end_idx:], True

    return content, False


def _norm_rel_path(p: str) -> str:
    s = p.strip().replace("\\", "/")
    while s.startswith("./"):
        s = s[2:]
    return s


def _resolve_source_file(source_dir: str, filepath: str, file_list: List[str]) -> Tuple[Optional[str], Optional[str]]:
    """Resolve a violation filepath to (rel_path, content) from the live checkout."""
    raw = filepath.strip()
    if not raw:
        return None, None
    norm_fp = _norm_rel_path(raw)
    root = pathlib.Path(source_dir)

    candidate = root / raw
    if candidate.is_file():
        return norm_fp, candidate.read_text(errors="replace")

    # Try normalised path
    candidate2 = root / norm_fp
    if candidate2.is_file():
        return norm_fp, candidate2.read_text(errors="replace")

    # Basename fallback
    base = pathlib.Path(norm_fp).name
    matches = [f for f in file_list if pathlib.Path(f).name == base]
    if len(matches) == 1:
        full = root / matches[0]
        if full.is_file():
            return _norm_rel_path(matches[0]), full.read_text(errors="replace")

    logger.warning("Cannot resolve remediation file %r in source dir", raw)
    return None, None


def apply_pipeline_fix_code_to_clone(
    remediation_actions: List[Dict[str, Any]],
    source_dir: str,
    file_list: List[str],
) -> Tuple[Dict[str, str], List[str], List[Dict[str, str]]]:
    """Apply fix_code patches from MCP remediation_actions to checked-out files.

    Returns (validated_fixes, failed_files, fix_table_rows).
    """
    validated_fixes: Dict[str, str] = {}
    failed_files: List[str] = []
    fix_table_rows: List[Dict[str, str]] = []

    by_file: Dict[str, List[Dict[str, Any]]] = {}
    for action in remediation_actions:
        fp = (action.get("file") or "").strip()
        if fp:
            by_file.setdefault(fp, []).append(action)

    for filepath, actions in by_file.items():
        has_fix_code = any(action.get("fix_code") for action in actions)
        if not has_fix_code:
            failed_files.append(filepath)
            continue

        rel_path, original_content = _resolve_source_file(source_dir, filepath, file_list)
        if rel_path is None or original_content is None:
            failed_files.append(filepath)
            continue

        content = original_content
        patch_applied = False
        for action in actions:
            for fix_entry in (action.get("fix_code") or []):
                original = fix_entry.get("original") or ""
                replacement = fix_entry.get("replacement", "")
                if not original.strip():
                    continue
                content, applied = _apply_fix_entry(content, original, replacement)
                if applied:
                    patch_applied = True
                else:
                    logger.debug(
                        "Patch not applied for %r — original snippet (%d chars) not found",
                        filepath, len(original),
                    )

        if patch_applied and content != original_content:
            validated_fixes[rel_path] = content
            for action in actions:
                fix_table_rows.append({
                    "policy": action.get("control", ""),
                    "description": (action.get("instruction") or "")[:200],
                    "file": filepath,
                })
        else:
            logger.warning("No patch applied for %r — snippets did not match file content", filepath)
            failed_files.append(filepath)

    return validated_fixes, failed_files, fix_table_rows


# ===========================================================================
# Remediation PR creation
# ===========================================================================

def _create_fix_pr(
    github_token: str,
    repo: str,
    branch: str,
    head_sha: str,
    validated_fixes: Dict[str, str],
    fix_table: List[Dict[str, str]],
    *,
    report: str = "",
    failed_files: Optional[List[str]] = None,
) -> Tuple[Optional[int], str]:
    """Commit fix_code patches to a remediation branch and open (or refresh) a PR."""
    try:
        import sys as _sys
        import os as _os
        _sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
        from scm_client import GitHubClient  # type: ignore
    except ImportError:
        logger.error("scm_client.py not found — cannot create remediation PR")
        return None, ""

    if not validated_fixes:
        return None, ""

    safe_branch = re.sub(r"[^a-zA-Z0-9._/-]", "-", branch)
    sha_short = head_sha[:7]
    timestamp = time.strftime("%m%d%H%M")
    remediation_branch = f"{REMEDIATION_BRANCH_PREFIX}-{safe_branch.replace('/', '-')}-{sha_short}-{timestamp}"

    scm = GitHubClient(token=github_token)

    # Resolve short SHA to full 40-char SHA (GitHub's /git/refs API requires it)
    if len(head_sha) < 40:
        try:
            commit_data = scm._request("GET", f"/repos/{repo}/commits/{head_sha}")
            head_sha = commit_data["sha"]
        except Exception as exc:
            logger.warning("Could not resolve short SHA %s: %s", head_sha, exc)

    try:
        logger.info("Creating remediation branch %s from %s", remediation_branch, sha_short)
        scm.create_branch(repo, remediation_branch, head_sha)
    except Exception as exc:
        logger.error("Failed to create/verify remediation branch: %s", exc)
        return None, remediation_branch

    committed: List[str] = []
    for filepath, content in validated_fixes.items():
        blob_sha: Optional[str] = None
        try:
            blob_sha = scm.get_file_blob_sha(repo, filepath, head_sha)
        except Exception:
            pass
        policies = ", ".join({r["policy"] for r in fix_table if r["file"] == filepath}) or "policy violations"
        message = f"fix({filepath}): remediate {policies} [unifai-gha-scan]"
        try:
            scm.commit_file(repo, remediation_branch, filepath, content.encode("utf-8"), message, sha=blob_sha)
            committed.append(filepath)
            logger.info("Committed fix: %s", filepath)
        except Exception as exc:
            logger.error("Failed to commit %s: %s", filepath, exc)

    if not committed:
        logger.warning("No files committed — skipping PR creation")
        return None, remediation_branch

    title = f"[unifai-bot] fix: AI policy remediation for {branch}@{sha_short}"

    files_list = "\n".join(f"- `{f}`" for f in committed)
    failed_list = ("\n".join(f"- `{f}`" for f in (failed_files or []))) or "_None_"
    pr_body_lines = [
        f"## UniFAI AI Policy Remediation",
        f"",
        f"Automated fixes for policy violations detected in `{branch}` at `{sha_short}`.",
        f"",
        f"### Files remediated ({len(committed)})",
        f"",
        files_list,
        f"",
        f"### Files without fixes ({len(failed_files or [])})",
        f"",
        failed_list,
    ]
    if report:
        MAX_REPORT_CHARS = 56_000  # leave room for rest of PR body; GitHub cap is 65536
        report_text = report.strip()
        if len(report_text) > MAX_REPORT_CHARS:
            report_text = report_text[:MAX_REPORT_CHARS] + "\n\n---\n\n*…Report truncated for GitHub PR body size limit. Retrieve the full text from CI logs.*"
        pr_body_lines += ["", "---", "", "<details><summary>Full scan report</summary>", "", report_text, "", "</details>"]
    pr_body = "\n".join(pr_body_lines)

    try:
        pr_number = scm.create_pull_request(repo, title, remediation_branch, branch, pr_body)
        logger.info("Created remediation PR #%d", pr_number)
        return pr_number, remediation_branch
    except Exception as exc:
        logger.error("Failed to create remediation PR: %s", exc)
        return None, remediation_branch


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
        print_human_output(output)
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
        print_human_output(output)
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
        print_human_output(output)
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
        print_human_output(output)
        return 1

    status = "compliant" if not all_violations else "violations_found"
    if failed_batches_count:
        status = "error"

    # Step 3: Remediation — apply fix_code patches and create PR
    remediation_pr_number: Optional[int] = None
    remediation_branch = ""
    failed_rem_files: List[str] = []

    github_token = (
        getattr(args, "github_token", None)
        or os.environ.get("GH_TOKEN", "")
        or os.environ.get("GITHUB_TOKEN", "")
    )
    if all_violations and github_token and getattr(args, "create_fix_pr", False):
        logger.info(
            "STEP 3: Applying fix_code patches for %d violation(s)", len(all_violations)
        )
        try:
            validated_fixes, failed_rem_files, fix_table = apply_pipeline_fix_code_to_clone(
                all_violations, source_path, file_list
            )
            logger.info(
                "Patches applied: %d file(s); no fix_code: %d file(s)",
                len(validated_fixes), len(failed_rem_files),
            )
            if validated_fixes:
                remediation_pr_number, remediation_branch = _create_fix_pr(
                    github_token, repo, branch, head_sha,
                    validated_fixes, fix_table,
                    report=combined_report, failed_files=failed_rem_files,
                )
            else:
                logger.warning("No patches could be applied — skipping PR creation")
        except Exception as exc:
            logger.error("Remediation step failed: %s", exc)
    elif all_violations:
        logger.info("Skipping remediation — GITHUB_TOKEN / --github-token not set")

    output = build_json_output(
        status=status, repo=repo, branch=branch, head_sha=head_sha,
        source_code_repo=source_code_repo, files_scanned=len(file_list),
        batches=len(batches), failed_batches=failed_batches_count,
        violations=all_violations, aibom=all_aibom, report=combined_report,
        remediation_pr=remediation_pr_number,
        remediation_branch=remediation_branch,
        failed_remediation_files=failed_rem_files,
        scan_errors=failure_details,
    )
    print_human_output(output)
    return 0

# ===========================================================================
# CLI
# ===========================================================================

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
        "--github-token", default="",
        help="GitHub token for creating remediation PRs (default: $GH_TOKEN then $GITHUB_TOKEN). "
             "If not set, violations are reported but no PR is created.",
    )
    parser.add_argument(
        "--create-fix-pr", default=False, action="store_true",
        help="Create a remediation PR with fix_code patches (default: false).",
    )
    parser.add_argument(
        "--debug", action="store_true",
        help="Enable DEBUG logging to stderr",
    )
    return parser.parse_args(argv or sys.argv[1:])


# ---------------------------------------------------------------------------
# Audit / decision logging
# ---------------------------------------------------------------------------
_AUDIT_LOG_PATH: str = os.environ.get(
    "LINEAJE_AUDIT_LOG",
    os.path.join(os.path.expanduser("~"), ".lineaje", "audit.jsonl"),
)
_MODEL_ID: str = os.environ.get("LINEAJE_MODEL_ID", "lineaje-mcp-scanner")
_MODEL_VERSION: str = os.environ.get("LINEAJE_MODEL_VERSION", "unknown")


def _compute_input_hash(args: argparse.Namespace) -> str:
    """Return a SHA-256 hex digest of the scan's key input parameters."""
    import hashlib, json as _json
    payload = _json.dumps(
        {
            "source_path": getattr(args, "source_path", "."),
            "repo": getattr(args, "repo", ""),
            "branch": getattr(args, "branch", ""),
            "head_sha": getattr(args, "head_sha", ""),
            "mcp_server_url": getattr(args, "mcp_server_url", ""),
        },
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def _write_audit_record(
    args: argparse.Namespace,
    exit_code: int,
    output_summary: str,
) -> None:
    """Append a single JSONL audit record to the persistent audit log.

    The record captures:
      - ISO-8601 UTC timestamp
      - principal (OS user + CI actor)
      - model identifier and version
      - SHA-256 hash of scan inputs
      - output summary / status
      - exit code
    """
    import json as _json, getpass, datetime

    record = {
        "timestamp": datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "principal": {
            "os_user": getpass.getuser(),
            "ci_actor": os.environ.get("GITHUB_ACTOR", ""),
            "run_id": os.environ.get("GITHUB_RUN_ID", ""),
        },
        "model": {
            "id": _MODEL_ID,
            "version": _MODEL_VERSION,
        },
        "input_hash": _compute_input_hash(args),
        "inputs": {
            "repo": getattr(args, "repo", ""),
            "branch": getattr(args, "branch", ""),
            "head_sha": getattr(args, "head_sha", ""),
            "mcp_server_url": getattr(args, "mcp_server_url", ""),
        },
        "output_summary": output_summary,
        "exit_code": exit_code,
    }

    log_dir = os.path.dirname(_AUDIT_LOG_PATH)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)

    # Open in append mode — never truncate; each line is one immutable record.
    with open(_AUDIT_LOG_PATH, "a", encoding="utf-8") as fh:
        fh.write(_json.dumps(record) + "\n")
        fh.flush()
        os.fsync(fh.fileno())

    logger.info("Audit record written to %s", _AUDIT_LOG_PATH)


# ---------------------------------------------------------------------------


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
        exit_code = _execute_scan(args)
        _write_audit_record(
            args,
            exit_code=exit_code,
            output_summary=f"scan completed with exit_code={exit_code}",
        )
        return exit_code
    except Exception:
        logger.exception("Unhandled error")
        err = {"status": "error", "scan_errors": ["Unhandled exception — see stderr logs"]}
        try:
            _write_audit_record(
                args,
                exit_code=1,
                output_summary="unhandled exception — see stderr logs",
            )
        except Exception as audit_exc:  # noqa: BLE001
            logger.warning("Failed to write audit record: %s", audit_exc)
        print_human_output(err)
        return 1


if __name__ == "__main__":
    sys.exit(main())
