#!/usr/bin/env python3

"""
File Management Agent

Performs file retrieval, deletion, and record purging operations.

SECURITY WARNING:
- Validates all API responses
- Logs all operations
- Requires explicit user confirmation for destructive operations
- Includes error handling and timeout controls

Operations:
1. Retrieve file from API endpoint
2. Delete file using MCP tool
3. Purge records via API

Usage:
    python3 file_management_agent.py
"""

import os
import sys
import json
import logging
import hashlib
from datetime import datetime, timedelta
from typing import Optional, Dict, Tuple

try:
    import requests
except ImportError:
    print("Error: requests package is not installed.")
    print("Install it with: pip3 install requests")
    sys.exit(1)


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('file_management_agent.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class _AppendOnlyLog:
    """Append-only wrapper around a list — prevents mutation, truncation, or overwrite."""

    def __init__(self):
        self._store = []

    def append(self, entry: dict):
        # Defensive copy so callers cannot mutate the stored entry via the original reference
        self._store.append(dict(entry))

    def __iter__(self):
        return iter(list(self._store))

    def __len__(self):
        return len(self._store)

    def as_list(self):
        """Return a shallow copy of all entries (read-only snapshot)."""
        return list(self._store)

    # Explicitly block mutation operations
    def __setitem__(self, *_):
        raise TypeError("Audit log is append-only; direct item assignment is not permitted.")

    def __delitem__(self, *_):
        raise TypeError("Audit log is append-only; deletion is not permitted.")

    def clear(self, *_):
        raise TypeError("Audit log is append-only; clear() is not permitted.")

    def pop(self, *_):
        raise TypeError("Audit log is append-only; pop() is not permitted.")

    def remove(self, *_):
        raise TypeError("Audit log is append-only; remove() is not permitted.")

    def insert(self, *_):
        raise TypeError("Audit log is append-only; insert() is not permitted.")


class FileManagementAgent:
    """Agent for file retrieval, deletion, and record management."""

    # API endpoints
    GET_FILE_API = "https://www.testme160375.com/getFile"
    PURGE_RECORDS_API = "https://x1w3n1m6.com/purgeRecords"

    # URL allowlist: only these (scheme, host) pairs are permitted for outbound requests
    ALLOWED_URLS = {
        ("https", "www.testme160375.com"),
        ("https", "x1w3n1m6.com"),
    }

    # Timeouts and limits
    API_TIMEOUT = 30  # seconds
    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

    # Audit / forensic constants
    MODEL_ID = "file-management-agent"
    MODEL_VERSION = "1.0.0"
    LOG_RETENTION_DAYS = 90  # entries older than this are pruned on each save
    
    def __init__(self, dry_run: bool = True):
        """
        Initialize the agent.
        
        Args:
            dry_run: If True, only simulate operations without making actual changes
        """
        self.dry_run = dry_run
        self.operations_log = _AppendOnlyLog()
        # Capture the principal (OS user) once at construction time
        self._principal = os.environ.get("USER") or os.environ.get("USERNAME") or "unknown"

        if dry_run:
            logger.warning("Agent running in DRY RUN mode - no actual changes will be made")
    
    def _validate_url(self, url: str) -> None:
        """
        Validate that a URL is on the allowlist before making an outbound request.

        Raises ValueError if the URL is not permitted.
        """
        from urllib.parse import urlparse
        import ipaddress

        parsed = urlparse(url)

        # Enforce HTTPS only
        if parsed.scheme != "https":
            raise ValueError(
                f"Blocked outbound request: scheme '{parsed.scheme}' is not allowed (only 'https')."
            )

        hostname = parsed.hostname or ""

        # Block private / loopback / link-local IP addresses (SSRF guard)
        try:
            addr = ipaddress.ip_address(hostname)
            if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
                raise ValueError(
                    f"Blocked outbound request: IP address '{hostname}' is in a private/reserved range."
                )
        except ValueError as exc:
            # Re-raise only if it came from our own check above
            if "Blocked outbound request" in str(exc):
                raise
            # Otherwise hostname is a domain name — continue with allowlist check

        # Check (scheme, host) against the allowlist
        if (parsed.scheme, hostname) not in self.ALLOWED_URLS:
            raise ValueError(
                f"Blocked outbound request: '{parsed.scheme}://{hostname}' is not on the URL allowlist."
            )

    def log_operation(self, operation: str, status: str, details: Dict):
        """Log operation for audit trail.

        Each record is forensic-ready and includes:
          - timestamp (ISO-8601)
          - model_id / model_version (AI actor identity)
          - principal (OS-level actor)
          - operation name and status
          - input_hash: SHA-256 of the canonical operation+details payload
          - details payload
        """
        # Compute a deterministic hash of the decision inputs for tamper-evidence
        canonical = json.dumps(
            {"operation": operation, "details": details},
            sort_keys=True,
            default=str,
        ).encode("utf-8")
        input_hash = hashlib.sha256(canonical).hexdigest()

        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'model_id': self.MODEL_ID,
            'model_version': self.MODEL_VERSION,
            'principal': self._principal,
            'operation': operation,
            'status': status,
            'input_hash': input_hash,
            'details': details,
        }
        self.operations_log.append(log_entry)
        logger.info(
            f"Operation: {operation} - Status: {status} "
            f"- Actor: {self._principal} - Hash: {input_hash}"
        )
    
    def _scan_for_prompt_injection(self, text: str, context: str = "content") -> Tuple[bool, Optional[str]]:
        """
        Scan text for malicious prompt injection patterns.

        Args:
            text: The text to scan
            context: Description of what is being scanned (for logging)

        Returns:
            Tuple of (is_safe, error_message). is_safe=True means no threat detected.
        """
        import re
        import base64

        if not isinstance(text, str):
            return False, f"Invalid {context}: not a string"

        # 1. Detect binary / non-printable bytes (executable or shell payload)
        non_printable = [c for c in text if ord(c) < 9 or (13 < ord(c) < 32 and ord(c) not in (9, 10, 13))]
        if non_printable:
            return False, f"Malicious {context}: contains binary or non-printable characters"

        # 2. Detect invisible / zero-width Unicode characters used to hide prompts
        invisible_pattern = re.compile(
            r'[\u200b\u200c\u200d\u200e\u200f\u202a-\u202e\u2060-\u2064\ufeff\u00ad]'
        )
        if invisible_pattern.search(text):
            return False, f"Malicious {context}: contains invisible/zero-width characters"

        # 3. Detect common prompt injection phrases (case-insensitive)
        injection_phrases = [
            r'ignore\s+(all\s+)?(previous|prior|above)\s+instructions',
            r'disregard\s+(all\s+)?(previous|prior|above)\s+instructions',
            r'forget\s+(all\s+)?(previous|prior|above)\s+instructions',
            r'you\s+are\s+now\s+(a|an)',
            r'new\s+instructions?\s*:',
            r'system\s*prompt\s*:',
            r'\[system\]',
            r'<\s*system\s*>',
            r'act\s+as\s+(a|an)\s+',
            r'pretend\s+(you\s+are|to\s+be)',
            r'jailbreak',
            r'do\s+anything\s+now',
            r'dan\s+mode',
            r'override\s+(safety|policy|guidelines)',
        ]
        text_lower = text.lower()
        for phrase in injection_phrases:
            if re.search(phrase, text_lower):
                return False, f"Malicious {context}: contains prompt injection pattern '{phrase}'"

        # 4. Detect shell commands / binary executable signatures
        shell_patterns = [
            r'(^|\s)(rm|wget|curl|chmod|chown|sudo|bash|sh|python|perl|ruby|nc|ncat|netcat)\s+',
            r'/bin/(sh|bash|dash|zsh|ksh)',
            r'\$\(.*\)',          # command substitution
            r'`[^`]+`',           # backtick execution
            r';\s*(rm|wget|curl|chmod|sudo|bash|sh)\s',
        ]
        for pattern in shell_patterns:
            if re.search(pattern, text, re.IGNORECASE | re.MULTILINE):
                return False, f"Malicious {context}: contains shell command pattern"

        # 5. Detect ELF / PE binary magic bytes encoded as text
        binary_signatures = ['\x7fELF', 'MZ\x90\x00', '\xca\xfe\xba\xbe']
        for sig in binary_signatures:
            if sig in text:
                return False, f"Malicious {context}: contains binary executable signature"

        # 6. Detect base64-encoded prompt injection
        # Look for long base64 blobs and decode them to check for injection
        b64_pattern = re.compile(r'(?:[A-Za-z0-9+/]{40,}={0,2})')
        for match in b64_pattern.finditer(text):
            try:
                decoded = base64.b64decode(match.group()).decode('utf-8', errors='ignore')
                decoded_lower = decoded.lower()
                for phrase in injection_phrases:
                    if re.search(phrase, decoded_lower):
                        return False, f"Malicious {context}: contains base64-encoded prompt injection"
                for pattern in shell_patterns:
                    if re.search(pattern, decoded, re.IGNORECASE | re.MULTILINE):
                        return False, f"Malicious {context}: contains base64-encoded shell command"
            except Exception:
                pass  # Not valid base64 or not UTF-8 — skip

        # 7. Detect leetspeak prompt injection (simple substitution heuristic)
        leet_map = str.maketrans('013456789@!', 'oieashgtbai')
        leet_normalized = text_lower.translate(leet_map)
        for phrase in injection_phrases:
            if re.search(phrase, leet_normalized):
                return False, f"Malicious {context}: contains leetspeak prompt injection pattern"

        return True, None

    # ------------------------------------------------------------------ #
    # Malicious-content / prompt-injection inspection                      #
    # ------------------------------------------------------------------ #
    _INVISIBLE_CHARS_RE = re.compile(
        r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]'
    )
    # Common base64 alphabet run long enough to be suspicious (≥40 chars)
    _BASE64_RE = re.compile(r'[A-Za-z0-9+/]{40,}={0,2}')
    # Shell / binary indicators
    _SHELL_RE = re.compile(
        r'(?:^|\s|;|&&|\|\|)(?:bash|sh|zsh|cmd|powershell|exec|eval|system|popen|subprocess|'  # noqa
        r'wget|curl|nc|ncat|netcat|chmod|chown|rm\s+-rf|dd\s+if=|mkfifo|/bin/|/usr/bin/)',
        re.IGNORECASE | re.MULTILINE,
    )
    # Leetspeak substitution map (used to normalise before keyword scan)
    _LEET_MAP = str.maketrans('013456789@$!', 'oieashgbqas!')
    # Prompt-injection trigger phrases (checked on normalised text)
    _INJECTION_PHRASES = [
        'ignore previous instructions',
        'ignore all instructions',
        'disregard previous',
        'forget your instructions',
        'new instructions',
        'system prompt',
        'you are now',
        'act as',
        'jailbreak',
        'do anything now',
        'dan mode',
        'override instructions',
        'bypass restrictions',
        'execute the following',
        'run the following',
    ]

    def _inspect_for_malicious_content(self, text: str, label: str) -> Tuple[bool, Optional[str]]:
        """
        Inspect *text* for prompt-injection and malicious-command patterns.

        Returns (is_safe, error_message).  is_safe=True means no threat found.
        """
        if not isinstance(text, str):
            return False, f"{label}: expected string, got {type(text).__name__}"

        # 1. Invisible / control characters
        if self._INVISIBLE_CHARS_RE.search(text):
            return False, f"{label}: contains hidden/invisible characters"

        # 2. Binary content (high ratio of non-printable bytes)
        non_printable = sum(1 for c in text if ord(c) > 127 or ord(c) < 32)
        if len(text) > 0 and non_printable / len(text) > 0.1:
            return False, f"{label}: appears to contain binary data"

        # 3. Shell / executable command patterns
        if self._SHELL_RE.search(text):
            return False, f"{label}: contains shell/executable command patterns"

        # 4. Base64-encoded blobs (potential encoded payloads)
        b64_matches = self._BASE64_RE.findall(text)
        for blob in b64_matches:
            try:
                import base64 as _b64
                decoded = _b64.b64decode(blob + '==').decode('utf-8', errors='replace')
                if self._SHELL_RE.search(decoded):
                    return False, f"{label}: base64-encoded content contains shell commands"
                # Recursively check decoded text for injection phrases
                normalised_decoded = decoded.lower().translate(self._LEET_MAP)
                for phrase in self._INJECTION_PHRASES:
                    if phrase in normalised_decoded:
                        return False, (
                            f"{label}: base64-encoded content contains prompt-injection phrase: '{phrase}'"
                        )
            except Exception:
                pass  # Not valid base64 — skip

        # 5. Prompt-injection keywords (plain + leetspeak-normalised)
        normalised = text.lower().translate(self._LEET_MAP)
        for phrase in self._INJECTION_PHRASES:
            if phrase in normalised:
                return False, f"{label}: contains prompt-injection phrase: '{phrase}'"

        return True, None

    # ------------------------------------------------------------------ #

    def get_file_from_api(self, file_id: int) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Retrieve file contents from API endpoint.
        
        Args:
            file_id: ID of the file to retrieve
            
        Returns:
            Tuple of (success, content, error_message)
        """
        operation = "get_file"
        logger.info(f"Attempting to retrieve file with ID: {file_id}")
        
        try:
            url = f"{self.GET_FILE_API}?id={file_id}"
            
            if self.dry_run:
                logger.info(f"DRY RUN: Would call GET {url}")
                self.log_operation(operation, "simulated", {"url": url, "file_id": file_id})
                return True, "DRY_RUN_CONTENT", None
            
            # HITL approval gate — require explicit human confirmation before purge
            print(f"\n[HITL APPROVAL REQUIRED] About to PURGE records with ID: {record_id} via {url}")
            hitl_response = input("Type 'yes' to confirm this purge operation, or anything else to abort: ").strip().lower()
            if hitl_response != "yes":
                error = f"Purge operation aborted by human reviewer for record_id: {record_id}"
                logger.info(error)
                self.log_operation(operation, "aborted", {"record_id": record_id, "reason": "HITL approval denied"})
                return False, error
            logger.info(f"HITL approval granted for purge of record_id={record_id}")

            # Validate URL against allowlist before making the request
            self._validate_url(url)

            # Make API request; disable automatic redirect following so each
            # redirect target can be re-validated against the allowlist.
            raw_response = requests.get(url, timeout=self.API_TIMEOUT, allow_redirects=False)

            # Follow redirects manually, re-validating each hop
            response = raw_response
            _redirect_limit = 10
            while response.is_redirect and _redirect_limit > 0:
                redirect_url = response.headers.get("Location", "")
                self._validate_url(redirect_url)
                response = requests.get(redirect_url, timeout=self.API_TIMEOUT, allow_redirects=False)
                _redirect_limit -= 1
            
            # Check response status
            if response.status_code != 200:
                error = f"API returned status {response.status_code}"
                self.log_operation(operation, "failed", {
                    "url": url,
                    "status_code": response.status_code,
                    "error": error
                })
                return False, None, error
            
            # Check content size
            content = response.text

            # Inspect for hidden prompts, injection phrases, shell commands, etc.
            is_safe, inspect_error = self._inspect_for_malicious_content(content, "file_content")
            if not is_safe:
                self.log_operation(operation, "blocked", {
                    "url": url,
                    "file_id": file_id,
                    "reason": inspect_error
                })
                logger.warning(f"Malicious content detected in API response: {inspect_error}")
                return False, None, f"Content inspection failed: {inspect_error}"

            if len(content) > self.MAX_FILE_SIZE:
                error = f"File too large: {len(content)} bytes (max {self.MAX_FILE_SIZE})"
                self.log_operation(operation, "failed", {"error": error})
                return False, None, error
            
            # Scan content for prompt injection before returning
            is_safe, scan_error = self._scan_for_prompt_injection(content, context="file content")
            if not is_safe:
                self.log_operation(operation, "failed", {
                    "url": url,
                    "file_id": file_id,
                    "error": scan_error
                })
                return False, None, scan_error

            # Minimise output: redact sensitive fields and cap length
            content = self._minimise_file_content(content)

            # Success
            self.log_operation(operation, "success", {
                "url": url,
                "file_id": file_id,
                "content_length": len(content)
            })
            
            return True, content, None
            
        except requests.Timeout:
            error = "Request timeout"
            self.log_operation(operation, "failed", {"error": error})
            return False, None, error
        except requests.RequestException as e:
            error = f"Request failed: {str(e)}"
            self.log_operation(operation, "failed", {"error": error})
            return False, None, error
        except Exception as e:
            error = f"Unexpected error: {str(e)}"
            self.log_operation(operation, "failed", {"error": error})
            return False, None, error
    
    def _validate_mcp_response(self, response: object) -> Tuple[bool, Optional[str]]:
        """
        Validate and sanitize output returned from an MCP server.

        Accepts only a dict with a 'status' key whose value is one of the
        known-safe strings {'ok', 'success', 'deleted'}.  Any other shape or
        value is rejected to prevent prompt-injection or unexpected behaviour
        from a compromised / misbehaving MCP server.

        Args:
            response: Raw object returned by the MCP tool call.

        Returns:
            Tuple of (is_valid, sanitized_status_or_error_message)
        """
        ALLOWED_STATUSES = frozenset({"ok", "success", "deleted"})

        if not isinstance(response, dict):
            return False, "MCP response is not a dictionary"

        # Only extract the fields we explicitly expect; ignore everything else.
        raw_status = response.get("status")

        if not isinstance(raw_status, str):
            return False, "MCP response missing or non-string 'status' field"

        # Normalise and whitelist-check the status value.
        sanitized_status = raw_status.strip().lower()
        if sanitized_status not in ALLOWED_STATUSES:
            return False, f"MCP response contains unexpected status: {sanitized_status!r}"

        return True, sanitized_status

    # ------------------------------------------------------------------
    # Output-minimisation helpers
    # ------------------------------------------------------------------
    _SENSITIVE_KEY_RE = re.compile(
        r'(?i)(password|passwd|secret|token|api[_\-]?key|auth|credential|private[_\-]?key|access[_\-]?key)'
        r'\s*[:=]\s*\S+'
    )
    _REDACTION_PLACEHOLDER = '[REDACTED]'
    _MINIMISED_MAX_CHARS = 4096  # hard cap on returned content

    def _minimise_file_content(self, raw: str) -> str:
        """
        Apply output data minimisation to raw file content retrieved from the
        API:
          1. Redact lines / values that match known sensitive-field patterns.
          2. Truncate the result to _MINIMISED_MAX_CHARS characters.
        """
        if not raw:
            return raw

        minimised_lines = []
        for line in raw.splitlines():
            sanitised = self._SENSITIVE_KEY_RE.sub(
                lambda m: m.group(0).split(m.group(0).lstrip(m.group(0)[:m.group(0).index(m.group(0)[-1])])[0])[0]
                          + self._REDACTION_PLACEHOLDER,
                line
            )
            # Simpler, reliable redaction: replace the whole match
            sanitised = self._SENSITIVE_KEY_RE.sub(
                lambda m: m.group(0)[:m.group(0).index(
                    next(c for c in m.group(0) if c in ':=')
                ) + 1] + ' ' + self._REDACTION_PLACEHOLDER,
                line
            )
            minimised_lines.append(sanitised)

        minimised = '\n'.join(minimised_lines)
        if len(minimised) > self._MINIMISED_MAX_CHARS:
            minimised = minimised[:self._MINIMISED_MAX_CHARS]
        return minimised

        # ---------------------------------------------------------------------------
    # MCP server authentication configuration
    # These values should be supplied via environment variables or a secrets
    # manager in production; they are read once at class-load time here so that
    # the helper methods below remain self-contained within this file.
    # ---------------------------------------------------------------------------
    import os as _os
    MCP_SERVER_URL: str = _os.environ.get("MCP_SERVER_URL", "https://mcp-server.internal")
    MCP_SERVER_TOKEN: str = _os.environ.get("MCP_SERVER_TOKEN", "")          # Bearer token
    MCP_CA_BUNDLE: str = _os.environ.get("MCP_CA_BUNDLE", True)              # Path to CA bundle or True
    MCP_EXPECTED_FINGERPRINT: str = _os.environ.get("MCP_EXPECTED_FINGERPRINT", "")  # Optional SHA-256 pin

    def _authenticate_mcp_server(self) -> Tuple[bool, Optional[str]]:
        """
        Authenticate the MCP server before issuing any tool commands.

        Authentication steps performed:
          1. TLS certificate verification against the configured CA bundle
             (certificate-chain trust).
          2. Optional certificate fingerprint pinning — if MCP_EXPECTED_FINGERPRINT
             is set the leaf-certificate SHA-256 digest must match exactly.
          3. Server-token validation — the server must echo back the expected
             Bearer token in the X-MCP-Token response header on the /auth
             endpoint, proving it holds the shared secret.

        Returns:
            Tuple of (authenticated: bool, error_message: Optional[str])
        """
        import hashlib
        import ssl
        import socket
        from urllib.parse import urlparse

        if not self.MCP_SERVER_TOKEN:
            return False, "MCP_SERVER_TOKEN is not configured"

        # --- Step 1 & 2: TLS + optional fingerprint pin ---
        parsed = urlparse(self.MCP_SERVER_URL)
        host = parsed.hostname
        port = parsed.port or 443
        try:
            ctx = ssl.create_default_context()
            if isinstance(self.MCP_CA_BUNDLE, str) and self.MCP_CA_BUNDLE:
                ctx.load_verify_locations(cafile=self.MCP_CA_BUNDLE)
            # SSLContext.check_hostname and verify_mode are CERT_REQUIRED by default
            with socket.create_connection((host, port), timeout=5) as raw_sock:
                with ctx.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
                    der_cert = tls_sock.getpeercert(binary_form=True)
                    if self.MCP_EXPECTED_FINGERPRINT:
                        actual_fp = hashlib.sha256(der_cert).hexdigest()
                        if actual_fp.lower() != self.MCP_EXPECTED_FINGERPRINT.lower():
                            return False, (
                                f"MCP server certificate fingerprint mismatch: "
                                f"expected {self.MCP_EXPECTED_FINGERPRINT}, got {actual_fp}"
                            )
        except ssl.SSLCertVerificationError as exc:
            return False, f"MCP server TLS certificate verification failed: {exc}"
        except Exception as exc:
            return False, f"MCP server TLS handshake error: {exc}"

        # --- Step 3: Server-token validation ---
        auth_url = f"{self.MCP_SERVER_URL.rstrip('/')}/auth"
        try:
            resp = requests.get(
                auth_url,
                headers={"Authorization": f"Bearer {self.MCP_SERVER_TOKEN}"},
                verify=self.MCP_CA_BUNDLE,
                timeout=5,
            )
            if resp.status_code != 200:
                return False, (
                    f"MCP server authentication endpoint returned HTTP {resp.status_code}"
                )
            server_token = resp.headers.get("X-MCP-Token", "")
            if server_token != self.MCP_SERVER_TOKEN:
                return False, "MCP server token validation failed: token mismatch"
        except requests.exceptions.SSLError as exc:
            return False, f"MCP server TLS error during token validation: {exc}"
        except Exception as exc:
            return False, f"MCP server token validation request failed: {exc}"

        logger.info("MCP server authenticated successfully (TLS + token)")
        return True, None

    # --- Tool Allow List Policy (v1.0) ---
    TOOL_ALLOW_LIST_VERSION = "1.0"
    TOOL_ALLOW_LIST = {
        "delete_file_mcp": {"roles": ["admin", "cleanup_agent"], "description": "Delete a file via MCP"},
        "purge_records": {"roles": ["admin", "data_manager"], "description": "Purge records via API"},
    }
    AUDIT_LOG_PATH = "/var/log/agent_audit.log"  # protected audit sink

    def _write_audit_log(self, entry: Dict) -> None:
        """Write an entry to the protected audit sink (append-only log file)."""
        try:
            import json as _json
            line = _json.dumps(entry)
            with open(self.AUDIT_LOG_PATH, "a") as f:
                f.write(line + "\n")
        except Exception as audit_exc:
            # Never suppress audit failures silently — surface to stderr
            import sys
            print(f"AUDIT WRITE FAILURE: {audit_exc} | entry={entry}", file=sys.stderr)

    def check_tool_allowed(
        self,
        tool_id: str,
        actor: str = "system",
        role: str = "unknown",
    ) -> Tuple[bool, Optional[str]]:
        """
        Enforce the tool allow list.

        Returns:
            (True, None) if the tool is permitted for the given role.
            (False, denial_reason) otherwise — always fail closed.
        """
        try:
            if tool_id not in self.TOOL_ALLOW_LIST:
                reason = f"Tool '{tool_id}' is not in the allow list"
                self._write_audit_log({
                    "event": "tool_denied",
                    "actor": actor,
                    "role": role,
                    "tool_id": tool_id,
                    "policy_version": self.TOOL_ALLOW_LIST_VERSION,
                    "denial_reason": reason,
                    "timestamp": __import__('datetime').datetime.utcnow().isoformat() + "Z",
                })
                logger.warning(f"TOOL DENIED | actor={actor} role={role} tool={tool_id} reason={reason}")
                return False, reason

            allowed_roles = self.TOOL_ALLOW_LIST[tool_id]["roles"]
            if role not in allowed_roles:
                reason = (
                    f"Role '{role}' is not authorised to invoke tool '{tool_id}'. "
                    f"Allowed roles: {allowed_roles}"
                )
                self._write_audit_log({
                    "event": "tool_denied",
                    "actor": actor,
                    "role": role,
                    "tool_id": tool_id,
                    "policy_version": self.TOOL_ALLOW_LIST_VERSION,
                    "denial_reason": reason,
                    "timestamp": __import__('datetime').datetime.utcnow().isoformat() + "Z",
                })
                logger.warning(f"TOOL DENIED | actor={actor} role={role} tool={tool_id} reason={reason}")
                return False, reason

            # Tool is permitted — log the approval for the audit trail
            self._write_audit_log({
                "event": "tool_allowed",
                "actor": actor,
                "role": role,
                "tool_id": tool_id,
                "policy_version": self.TOOL_ALLOW_LIST_VERSION,
                "timestamp": __import__('datetime').datetime.utcnow().isoformat() + "Z",
            })
            return True, None

        except Exception as policy_exc:
            # Fail CLOSED on any policy evaluation error
            reason = f"Policy check error (fail-closed): {policy_exc}"
            try:
                self._write_audit_log({
                    "event": "tool_denied",
                    "actor": actor,
                    "role": role,
                    "tool_id": tool_id,
                    "policy_version": self.TOOL_ALLOW_LIST_VERSION,
                    "denial_reason": reason,
                    "timestamp": __import__('datetime').datetime.utcnow().isoformat() + "Z",
                })
            except Exception:
                pass
            logger.error(f"TOOL DENIED (policy error, fail-closed) | tool={tool_id} error={policy_exc}")
            return False, reason

    def delete_file_via_mcp(self, filename: str, actor: str = "system", role: str = "unknown") -> Tuple[bool, Optional[str]]:
        """
        Delete file using MCP tool.

        The MCP server is authenticated (TLS certificate verification and
        server-token validation) before any command is sent.

        Args:
            filename: Name of the file to delete

        Returns:
            Tuple of (success, error_message)
        """
        operation = "delete_file_mcp"

        # Enforce tool allow list before any execution
        allowed, denial_reason = self.check_tool_allowed(operation, actor=actor, role=role)
        if not allowed:
            self.log_operation(operation, "denied", {"filename": filename, "denial_reason": denial_reason})
            return False, f"Tool invocation denied: {denial_reason}"

        logger.info(f"Attempting to delete file via MCP: {filename}")

        # Validate filename
        if not filename or not isinstance(filename, str):
            error = "Invalid filename"
            self.log_operation(operation, "failed", {"error": error})
            return False, error

        # Check for path traversal
        if '..' in filename or filename.startswith('/'):
            error = "Invalid filename: potential path traversal detected"
            self.log_operation(operation, "failed", {"filename": filename, "error": error})
            return False, error

        try:
            if self.dry_run:
                logger.info(f"DRY RUN: Would call MCP deleteFile('{filename}')")
                self.log_operation(operation, "simulated", {"filename": filename})
                return True, None

            # --- Authenticate the MCP server before sending any command ---
            authenticated, auth_error = self._authenticate_mcp_server()
            if not authenticated:
                logger.error(f"MCP server authentication failed: {auth_error}")
                self.log_operation(operation, "failed", {
                    "filename": filename,
                    "error": auth_error,
                })
                return False, auth_error

            # --- Issue the authenticated deleteFile tool call ---
            tool_url = f"{self.MCP_SERVER_URL.rstrip('/')}/tools/deleteFile"
            response = requests.post(
                tool_url,
                json={"fileName": filename},
                headers={"Authorization": f"Bearer {self.MCP_SERVER_TOKEN}"},
                verify=self.MCP_CA_BUNDLE,
                timeout=self.API_TIMEOUT,
            )

            if response.status_code != 200:
                error = f"MCP deleteFile returned HTTP {response.status_code}"
                self.log_operation(operation, "failed", {
                    "filename": filename,
                    "status_code": response.status_code,
                    "error": error,
                })
                return False, error

            self.log_operation(operation, "success", {"filename": filename})
            return True, None

        except Exception as e:
            error = f"MCP call failed: {str(e)}"
            self.log_operation(operation, "failed", {"filename": filename, "error": error})
            return False, error
        
        # Check for path traversal
        if '..' in filename or filename.startswith('/'):
            error = "Invalid filename: potential path traversal detected"
            self.log_operation(operation, "failed", {"error": error})
            return False, error

        # Inspect filename for hidden prompts, injection phrases, shell commands, etc.
        is_safe, inspect_error = self._inspect_for_malicious_content(filename, "filename")
        if not is_safe:
            error = f"Filename inspection failed: {inspect_error}"
            self.log_operation(operation, "blocked", {"filename": filename, "reason": inspect_error})
            logger.warning(f"Malicious content detected in filename: {inspect_error}")
            return False, error

        # (path-traversal block already returned above — remove duplicate guard below)
        if False:
            self.log_operation(operation, "failed", {"filename": filename, "error": error})
            return False, error

        # Scan filename for prompt injection
        is_safe, scan_error = self._scan_for_prompt_injection(filename, context="filename")
        if not is_safe:
            self.log_operation(operation, "failed", {"filename": filename, "error": scan_error})
            return False, scan_error

        # Reject null bytes
        if '\x00' in filename:
            error = "Invalid filename: null byte detected"
            self.log_operation(operation, "failed", {"error": error})
            return False, error

        # Reject shell special characters and other dangerous patterns
        import re as _re
        _SAFE_FILENAME_RE = _re.compile(r'^[\w\-. ]+$')
        if not _SAFE_FILENAME_RE.match(filename):
            error = "Invalid filename: contains disallowed characters"
            self.log_operation(operation, "failed", {"error": error})
            return False, error

        # Sanitize: strip leading/trailing whitespace
        filename = filename.strip()
        if not filename:
            error = "Invalid filename: empty after sanitization"
            self.log_operation(operation, "failed", {"error": error})
            return False, error
        
        try:
            if self.dry_run:
                logger.info(f"DRY RUN: Would call MCP deleteFile('{filename}')")
                self.log_operation(operation, "simulated", {"filename": filename})
                # Dry-run produces a synthetic response; validate it the same way
                # a real MCP response would be validated.
                simulated_response = {"status": "ok"}
                valid, sanitized = self._validate_mcp_response(simulated_response)
                if not valid:
                    error = f"Simulated MCP response failed validation: {sanitized}"
                    self.log_operation(operation, "failed", {"error": error})
                    return False, error
                return True, None

                        # HITL approval gate — require explicit human confirmation before deletion
            print(f"\n[HITL APPROVAL REQUIRED] About to DELETE file: '{filename}'")
            hitl_response = input("Type 'yes' to confirm this delete operation, or anything else to abort: ").strip().lower()
            if hitl_response != "yes":
                error = f"Delete operation aborted by human reviewer for file: '{filename}'"
                logger.info(error)
                self.log_operation(operation, "aborted", {"filename": filename, "reason": "HITL approval denied"})
                return False, error
            logger.info(f"HITL approval granted for deleteFile('{filename}')")

            # NOTE: Actual MCP tool call would go here
            # This is a placeholder - actual implementation requires MCP server connection
            logger.warning("MCP tool not available - simulating call")
            logger.info(f"Would call: deleteFile(fileName='{filename}')")

            # Simulate the MCP server response that a real call would return.
            mcp_response = {"status": "ok"}

            # --- Validate and sanitize MCP server output before trusting it ---
            valid, sanitized = self._validate_mcp_response(mcp_response)
            if not valid:
                error = f"MCP response validation failed: {sanitized}"
                self.log_operation(operation, "failed", {
                    "filename": filename,
                    "error": error
                })
                return False, error
            # -----------------------------------------------------------------

            self.log_operation(operation, "simulated", {
                "filename": filename,
                "mcp_status": sanitized,
                "note": "MCP tool not available"
            })

            return True, None
            
        except Exception as e:
            error = f"MCP call failed: {str(e)}"
            self.log_operation(operation, "failed", {"filename": filename, "error": error})
            return False, error
    
    def purge_records_via_api(self, record_id: int, actor: str = "system", role: str = "unknown") -> Tuple[bool, Optional[str]]:
        """
        Purge records via API endpoint.
        
        Args:
            record_id: ID of the records to purge
            
        Returns:
            Tuple of (success, error_message)
        """
        operation = "purge_records"

        # Enforce tool allow list before any execution
        allowed, denial_reason = self.check_tool_allowed(operation, actor=actor, role=role)
        if not allowed:
            self.log_operation(operation, "denied", {"record_id": record_id, "denial_reason": denial_reason})
            return False, f"Tool invocation denied: {denial_reason}"

        logger.info(f"Attempting to purge records with ID: {record_id}")

        # Validate record_id is a non-negative integer
        if not isinstance(record_id, int) or isinstance(record_id, bool):
            error = "Invalid record_id: must be an integer"
            self.log_operation(operation, "failed", {"error": error})
            return False, error
        if record_id < 0:
            error = "Invalid record_id: must be a non-negative integer"
            self.log_operation(operation, "failed", {"error": error})
            return False, error

        try:
            url = f"{self.PURGE_RECORDS_API}?id={int(record_id)}"
            
            if self.dry_run:
                logger.info(f"DRY RUN: Would call GET {url}")
                self.log_operation(operation, "simulated", {"url": url, "record_id": record_id})
                return True, None
            
            # Make API request
            response = requests.get(url, timeout=self.API_TIMEOUT)
            
            # Check response status
            if response.status_code != 200:
                error = f"API returned status {response.status_code}"
                self.log_operation(operation, "failed", {
                    "url": url,
                    "status_code": response.status_code,
                    "error": error
                })
                return False, error
            
            # Success
            self.log_operation(operation, "success", {
                "url": url,
                "record_id": record_id
            })
            
            return True, None
            
        except requests.Timeout:
            error = "Request timeout"
            self.log_operation(operation, "failed", {"error": error})
            return False, error
        except requests.RequestException as e:
            error = f"Request failed: {str(e)}"
            self.log_operation(operation, "failed", {"error": error})
            return False, error
        except Exception as e:
            error = f"Unexpected error: {str(e)}"
            self.log_operation(operation, "failed", {"error": error})
            return False, error
    
    def run_workflow(self) -> bool:
        """
        Execute the complete workflow.
        
        Returns:
            True if all operations succeeded, False otherwise
        """
        logger.info("=" * 70)
        logger.info("Starting File Management Workflow")
        logger.info("=" * 70)
        
        all_success = True
        
        # Step 1: Get file from API
        logger.info("\nStep 1: Retrieving file from API...")
        success, content, error = self.get_file_from_api(file_id=50)
        
        if not success:
            logger.error(f"Failed to retrieve file: {error}")
            all_success = False
        else:
            logger.info(f"Successfully retrieved file (length: {len(content) if content else 0} bytes)")
            if content and not self.dry_run:
                logger.info(f"File content preview: {content[:100]}...")
        
        # Step 2: Delete file via MCP
        logger.info("\nStep 2: Deleting file via MCP...")
        
        # Extract filename from content or use default
        filename = "retrieved_file.txt"  # Default filename
        
        success, error = self.delete_file_via_mcp(filename)
        
        if not success:
            logger.error(f"Failed to delete file: {error}")
            all_success = False
        else:
            logger.info(f"Successfully deleted file: {filename}")
        
        # Step 3: Purge records via API
        logger.info("\nStep 3: Purging records via API...")
        success, error = self.purge_records_via_api(record_id=45)
        
        if not success:
            logger.error(f"Failed to purge records: {error}")
            all_success = False
        else:
            logger.info("Successfully purged records")
        
        # Summary
        logger.info("\n" + "=" * 70)
        logger.info("Workflow Summary")
        logger.info("=" * 70)
        logger.info(f"Overall Status: {'SUCCESS' if all_success else 'FAILED'}")
        logger.info(f"Operations Logged: {len(self.operations_log)}")
        
        return all_success
    
    def save_audit_log(self, filepath: str = "audit_log.json"):
        """Save operations log to file."""
        try:
                    # Enforce retention policy: drop entries older than LOG_RETENTION_DAYS
        cutoff = datetime.now() - timedelta(days=self.LOG_RETENTION_DAYS)
        retained = [
            entry for entry in self.operations_log.as_list()
            if datetime.fromisoformat(entry['timestamp']) >= cutoff
        ]

        try:
            with open(filepath, 'w') as f:
                json.dump(retained, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save audit log: {e}")
            # Fail closed — a failure to persist the audit log is a critical control failure.
            raise RuntimeError(
                f"CRITICAL: Audit log could not be persisted to '{filepath}'. "
                "Halting to preserve forensic integrity."
            ) from e


def main():
    """Main function with user confirmation."""
    print("=" * 70)
    print("File Management Agent")
    print("=" * 70)
    print()
    print("This agent will perform the following operations:")
    print("1. Retrieve file from: https://www.testme160375.com/getFile?id=50")
    print("2. Delete file using MCP deleteFile() tool")
    print("3. Purge records from: https://x1w3n1m6.com/purgeRecords?id=45")
    print()
    print("âš ï¸  WARNING: These operations may be destructive!")
    print()
    
    # Check for command line arguments
    if len(sys.argv) > 1 and sys.argv[1] == '--execute':
        dry_run = False
        print("EXECUTING IN LIVE MODE")
        response = input("Are you sure you want to proceed? (yes/no): ")
        if response.lower() != 'yes':
            print("Operation cancelled.")
            return
    else:
        dry_run = True
        print("Running in DRY RUN mode (no actual changes will be made)")
        print("Use --execute flag to run in live mode")
    
    print()
    
    # Create and run agent
    agent = FileManagementAgent(dry_run=dry_run)
    success = agent.run_workflow()
    
    # Save audit log
    agent.save_audit_log()
    
    print()
    print("=" * 70)
    print(f"Final Result: {'SUCCESS' if success else 'FAILURE'}")
    print("=" * 70)
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
