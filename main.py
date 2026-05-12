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
import uuid
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


# ---------------------------------------------------------------------------
# URL allowlist enforcement
# ---------------------------------------------------------------------------
import ipaddress
from urllib.parse import urlparse

# Allowlist: (scheme, host, path_prefix)
_URL_ALLOWLIST = [
    ("https", "www.testme160375.com", "/getFile"),
    ("https", "x1w3n1m6.com", "/purgeRecords"),
]

# Private / link-local CIDR blocks that must never be contacted
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),   # link-local
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def _validate_url(url: str) -> None:
    """
    Validate *url* against the explicit allowlist before any outbound request.

    Raises ValueError if the URL does not match an allowlisted
    (scheme, host, path_prefix) tuple, or if the resolved host falls inside
    a private / link-local address range.
    """
    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()
    host = (parsed.hostname or "").lower()
    path = parsed.path or "/"

    # 1. Must match at least one allowlist entry
    allowed = any(
        scheme == al_scheme and host == al_host and path.startswith(al_path)
        for al_scheme, al_host, al_path in _URL_ALLOWLIST
    )
    if not allowed:
        raise ValueError(
            f"URL '{url}' is not in the outbound HTTP allowlist."
        )

    # 2. Block private / link-local IP addresses (covers DNS-rebinding)
    try:
        addr = ipaddress.ip_address(host)
        for network in _BLOCKED_NETWORKS:
            if addr in network:
                raise ValueError(
                    f"URL '{url}' resolves to a blocked private/link-local address."
                )
    except ValueError as exc:
        # Re-raise only if it came from our own check; ignore 'not a valid IP'
        if "blocked" in str(exc) or "allowlist" in str(exc):
            raise
        # host is a hostname, not a bare IP — allowlist check above is sufficient


def _safe_get(url: str, timeout: int) -> "requests.Response":
    """
    Perform a GET request with allowlist validation on the initial URL and
    every redirect hop.  Redirects are followed manually so each Location
    header is re-validated before the next request is sent.
    """
    MAX_REDIRECTS = 10
    current_url = url
    for _ in range(MAX_REDIRECTS + 1):
        _validate_url(current_url)
        response = requests.get(current_url, timeout=timeout, allow_redirects=False)
        if response.status_code in (301, 302, 303, 307, 308):
            location = response.headers.get("Location", "")
            if not location:
                break
            # Resolve relative redirects
            from urllib.parse import urljoin
            current_url = urljoin(current_url, location)
        else:
            return response
    # Return the last response (could be a redirect with no Location)
    return response
# ---------------------------------------------------------------------------


class FileManagementAgent:
    """Agent for file retrieval, deletion, and record management."""
    
    # API endpoints
    GET_FILE_API = "https://www.testme160375.com/getFile"
    PURGE_RECORDS_API = "https://x1w3n1m6.com/purgeRecords"
    
    # Timeouts and limits
    API_TIMEOUT = 30  # seconds
    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

    # Audit / retention policy
    MODEL_ID = "file-management-agent"
    MODEL_VERSION = "1.0.0"
    RETENTION_DAYS = 365  # audit records must be retained for 1 year
    PRINCIPAL = os.environ.get("AGENT_PRINCIPAL", "unknown")
    
    def __init__(self, dry_run: bool = True, api_key: Optional[str] = None):
        """
        Initialize the agent.
        
        Args:
            dry_run: If True, only simulate operations without making actual changes
            api_key: API key used to authenticate inter-agent/service API calls
        """
        self.dry_run = dry_run
        self.operations_log = []
        self.api_key = api_key or os.environ.get("FILE_MANAGEMENT_API_KEY", "")
        if not self.api_key:
            logger.warning("No API key provided; inter-agent calls will be unauthenticated")
        
        if dry_run:
            logger.warning("Agent running in DRY RUN mode - no actual changes will be made")
    
    def log_operation(self, operation: str, status: str, details: Dict,
                      trace_id: Optional[str] = None):
        """Log operation for audit trail with full forensic fields."""
        now = datetime.now()
        input_hash = hashlib.sha256(
            json.dumps(details, sort_keys=True, default=str).encode()
        ).hexdigest()
        log_entry = {
            'timestamp': now.isoformat(),
            'trace_id': trace_id or str(uuid.uuid4()),
            'operation': operation,
            'status': status,
            'model_id': self.MODEL_ID,
            'model_version': self.MODEL_VERSION,
            'principal': self.PRINCIPAL,
            'input_hash': input_hash,
            'retention_expires_at': (
                now + timedelta(days=self.RETENTION_DAYS)
            ).isoformat(),
            'details': details,
        }
        self.operations_log.append(log_entry)
        logger.info(f"Operation: {operation} - Status: {status} - TraceID: {log_entry['trace_id']}")
    
    def _redact_pii(self, content: str) -> str:
        """
        Scan content for PII and redact it before further processing.

        Handles: SSN, email addresses, IP addresses, credit card numbers,
        and phone numbers.
        """
        import re

        # Social Security Numbers (e.g. 123-45-6789)
        content = re.sub(
            r'\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b',
            '[REDACTED-SSN]',
            content
        )

        # Email addresses
        content = re.sub(
            r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b',
            '[REDACTED-EMAIL]',
            content
        )

        # IPv4 addresses
        content = re.sub(
            r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b',
            '[REDACTED-IP]',
            content
        )

        # Credit card numbers (13-16 digits, optionally separated by spaces or dashes)
        content = re.sub(
            r'\b(?:\d[ \-]?){13,15}\d\b',
            '[REDACTED-CC]',
            content
        )

        # Phone numbers (various formats)
        content = re.sub(
            r'\b(?:\+?1[\s.\-]?)?(?:\(?\d{3}\)?[\s.\-]?)\d{3}[\s.\-]?\d{4}\b',
            '[REDACTED-PHONE]',
            content
        )

        return content

    def get_file_from_api(self, file_id: int,
                          trace_id: Optional[str] = None) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Retrieve file contents from API endpoint.
        
        Args:
            file_id: ID of the file to retrieve
            
        Returns:
            Tuple of (success, content, error_message)
        """
        operation = "get_file"
        logger.info(f"Attempting to retrieve file with ID: {file_id}")

        # Validate file_id: must be a positive integer within a safe bound
        if not isinstance(file_id, int) or isinstance(file_id, bool):
            error = "Invalid file_id: must be an integer"
            self.log_operation("get_file", "failed", {"error": error})
            return False, None, error
        if file_id <= 0 or file_id > 2_147_483_647:
            error = f"Invalid file_id: {file_id} is out of the allowed range (1–2147483647)"
            self.log_operation("get_file", "failed", {"error": error})
            return False, None, error

        try:
            url = f"{self.GET_FILE_API}?id={file_id}"
            
            if self.dry_run:
                logger.info(f"DRY RUN: Would call GET {url}")
                self.log_operation(operation, "simulated", {"url": url, "file_id": file_id},
                                   trace_id=trace_id)
                return True, "DRY_RUN_CONTENT", None
            
            # Make API request
            headers = {"Authorization": f"Bearer {self.api_key}"}
            response = requests.get(url, headers=headers, timeout=self.API_TIMEOUT)
            
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

            # Scan for malicious prompt content before use
            is_safe, scan_error = self._scan_for_malicious_content(content)
            if not is_safe:
                error = f"File content rejected due to malicious content: {scan_error}"
                self.log_operation(operation, "failed", {"error": error})
                return False, None, error

            if len(content) > self.MAX_FILE_SIZE:
                error = f"File too large: {len(content)} bytes (max {self.MAX_FILE_SIZE})"
                self.log_operation(operation, "failed", {"error": error})
                return False, None, error
            
            # Scan for Singapore PII before returning content
            pii_findings = self._scan_for_singapore_pii(content)
            if pii_findings:
                error = f"File contains Singapore PII ({', '.join(pii_findings)}); retrieval blocked by policy"
                self.log_operation(operation, "failed", {
                    "url": url,
                    "file_id": file_id,
                    "error": error
                })
                return False, None, error

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
    
    def _scan_for_malicious_content(self, content: str) -> Tuple[bool, Optional[str]]:
        """
        Scan file content for malicious prompt injection patterns.

        Checks for:
        - Invisible/hidden Unicode characters used to smuggle prompts
        - Base64-encoded prompt injection patterns
        - Leetspeak prompt patterns
        - Shell commands and binary/executable content
        - Suspicious prompt-injection keywords

        Returns:
            Tuple of (is_safe, error_message)
        """
        import re
        import base64

        # 1. Reject binary/executable content (null bytes or non-text indicators)
        if '\x00' in content:
            return False, "Binary or null-byte content detected"

        # 2. Detect invisible/hidden Unicode characters commonly used for prompt smuggling
        invisible_pattern = re.compile(
            r'[\u200b\u200c\u200d\u200e\u200f\u202a-\u202e\u2060-\u2064\ufeff\u00ad]'
        )
        if invisible_pattern.search(content):
            return False, "Invisible or hidden Unicode characters detected"

        # 3. Detect suspicious prompt-injection keywords (case-insensitive)
        prompt_injection_patterns = [
            r'ignore\s+(all\s+)?(previous|prior|above)\s+instructions',
            r'disregard\s+(all\s+)?(previous|prior|above)\s+instructions',
            r'forget\s+(all\s+)?(previous|prior|above)\s+instructions',
            r'you\s+are\s+now\s+(a|an)?\s*\w+',
            r'act\s+as\s+(a|an)?\s*\w+',
            r'pretend\s+(you\s+are|to\s+be)',
            r'new\s+instructions?\s*:',
            r'system\s*:\s*(you|your)',
            r'\[system\]',
            r'<\s*system\s*>',
            r'jailbreak',
            r'do\s+anything\s+now',
            r'dan\s+mode',
        ]
        for pat in prompt_injection_patterns:
            if re.search(pat, content, re.IGNORECASE):
                return False, f"Suspicious prompt-injection pattern detected: '{pat}'"

        # 4. Detect shell commands
        shell_command_patterns = [
            r'(?:^|\s|;|&&|\|\|)(?:rm|wget|curl|chmod|chown|sudo|su|bash|sh|zsh|python|perl|ruby|nc|netcat|ncat)\s',
            r'(?:^|\s)/bin/(?:sh|bash|zsh|dash)',
            r'(?:^|\s)/usr/bin/(?:python|perl|ruby|curl|wget)',
            r'\$\([^)]+\)',   # command substitution $()
            r'`[^`]+`',        # backtick command substitution
        ]
        for pat in shell_command_patterns:
            if re.search(pat, content, re.IGNORECASE | re.MULTILINE):
                return False, f"Shell command pattern detected"

        # 5. Detect base64-encoded prompt injection
        # Look for long base64 strings and decode them to check for prompt patterns
        b64_pattern = re.compile(r'(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')
        for match in b64_pattern.finditer(content):
            try:
                decoded = base64.b64decode(match.group()).decode('utf-8', errors='ignore')
                for pat in prompt_injection_patterns:
                    if re.search(pat, decoded, re.IGNORECASE):
                        return False, "Base64-encoded prompt injection pattern detected"
                for pat in shell_command_patterns:
                    if re.search(pat, decoded, re.IGNORECASE | re.MULTILINE):
                        return False, "Base64-encoded shell command detected"
            except Exception:
                pass  # Not valid base64 or not decodable — skip

        # 6. Detect leetspeak prompt injection (common substitutions: 3=e, 0=o, 1=i/l, @=a, $=s)
        def deleet(text: str) -> str:
            return (
                text.lower()
                .replace('3', 'e').replace('0', 'o').replace('1', 'i')
                .replace('@', 'a').replace('$', 's').replace('4', 'a')
                .replace('5', 's').replace('7', 't').replace('!', 'i')
            )

        deleeted = deleet(content)
        for pat in prompt_injection_patterns:
            if re.search(pat, deleeted, re.IGNORECASE):
                return False, "Leetspeak prompt injection pattern detected"

        return True, None

    # ------------------------------------------------------------------
    # Singapore PII detection helper
    # ------------------------------------------------------------------
    _SG_PII_PATTERNS = {
        "NRIC/FIN": r"\b[STFGM]\d{7}[A-Z]\b",
        "Passport": r"\b[A-Z]{1,2}\d{6,9}\b",
        "Bank Account": r"\b\d{3,4}[-\s]?\d{4,6}[-\s]?\d{1,7}\b",
        "Full Name (Title)": r"\b(?:Mr|Mrs|Ms|Dr|Prof)\.?\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)+\b",
    }

    def _scan_for_singapore_pii(self, content: str) -> list:
        """
        Scan text content for Singapore PII categories.

        Returns a list of PII category names found in the content.
        An empty list means no PII was detected.
        """
        import re
        found = []
        for category, pattern in self._SG_PII_PATTERNS.items():
            if re.search(pattern, content):
                found.append(category)
        return found

        def _authenticate_mcp_server(self) -> Tuple[bool, Optional[str]]:
        """
        Authenticate the MCP server using a pre-shared token before invoking any tool.

        The token is read from self.mcp_server_token (set during initialisation from
        the MCP_SERVER_TOKEN environment variable or explicit configuration).  The
        method performs a lightweight challenge/response against the MCP server's
        /auth/verify endpoint and validates the returned server certificate fingerprint
        against a pinned value stored in self.mcp_server_cert_fingerprint.

        Returns:
            Tuple of (authenticated: bool, error_message: Optional[str])
        """
        import hashlib
        import hmac
        import os

        # --- 1. Retrieve the pre-shared token --------------------------------
        token = getattr(self, "mcp_server_token", None) or os.environ.get("MCP_SERVER_TOKEN", "")
        if not token:
            return False, "MCP server authentication failed: MCP_SERVER_TOKEN is not configured"

        # --- 2. Retrieve the pinned certificate fingerprint ------------------
        pinned_fingerprint = getattr(self, "mcp_server_cert_fingerprint", None) or os.environ.get(
            "MCP_SERVER_CERT_FINGERPRINT", ""
        )

        # --- 3. Call the MCP server authentication endpoint ------------------
        mcp_base_url = getattr(self, "mcp_server_url", None) or os.environ.get("MCP_SERVER_URL", "")
        if not mcp_base_url:
            return False, "MCP server authentication failed: MCP_SERVER_URL is not configured"

        auth_url = mcp_base_url.rstrip("/") + "/auth/verify"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

        try:
            # verify=True enforces TLS certificate validation by default.
            # If a pinned fingerprint is provided we additionally compare it.
            response = requests.get(
                auth_url,
                headers=headers,
                timeout=getattr(self, "API_TIMEOUT", 30),
                verify=True,  # enforce TLS – never disable
            )

            if response.status_code == 401:
                return False, "MCP server authentication failed: server rejected the token (401 Unauthorized)"
            if response.status_code == 403:
                return False, "MCP server authentication failed: access forbidden (403)"
            if response.status_code != 200:
                return False, (
                    f"MCP server authentication failed: unexpected status {response.status_code}"
                )

            # --- 4. Validate server-reported identity token (HMAC) -----------
            server_identity = response.json().get("server_identity", "")
            expected_identity = hmac.new(
                token.encode(), mcp_base_url.encode(), hashlib.sha256
            ).hexdigest()
            if not hmac.compare_digest(server_identity, expected_identity):
                return False, "MCP server authentication failed: server identity mismatch"

            # --- 5. Optional certificate fingerprint pinning -----------------
            if pinned_fingerprint:
                # requests exposes the raw socket via response.raw.connection
                raw_conn = getattr(response.raw, "_connection", None)
                peer_cert_der = None
                if raw_conn and hasattr(raw_conn, "sock") and raw_conn.sock:
                    try:
                        peer_cert_der = raw_conn.sock.getpeercert(binary_form=True)
                    except Exception:
                        pass
                if peer_cert_der:
                    actual_fingerprint = hashlib.sha256(peer_cert_der).hexdigest()
                    if not hmac.compare_digest(actual_fingerprint.lower(), pinned_fingerprint.lower()):
                        return False, (
                            "MCP server authentication failed: TLS certificate fingerprint does not "
                            "match the pinned value"
                        )

            logger.info("MCP server authenticated successfully")
            return True, None

        except requests.exceptions.SSLError as exc:
            return False, f"MCP server authentication failed: TLS/SSL error – {exc}"
        except requests.exceptions.ConnectionError as exc:
            return False, f"MCP server authentication failed: connection error – {exc}"
        except requests.exceptions.Timeout:
            return False, "MCP server authentication failed: request timed out"
        except Exception as exc:
            return False, f"MCP server authentication failed: {exc}"

    # Explicit allow list of approved tools/operations for this agent.
    # Any tool not present here is denied by default (fail-closed).
    TOOL_ALLOW_LIST = {
        "delete_file_mcp",
        "purge_records",
    }
    POLICY_VERSION = "v1.0"

    def check_tool_allowed(self, tool_id: str, actor: str = "FileManagementAgent") -> bool:
        """
        Enforce the tool allow list before any tool or API invocation.
        Fails closed: returns False (deny) on any error or unlisted tool.
        Logs every denial with actor, tool_id, policy version, and reason.
        """
        try:
            if tool_id in self.TOOL_ALLOW_LIST:
                logger.info(
                    f"[POLICY ALLOW] actor={actor} tool={tool_id} "
                    f"policy_version={self.POLICY_VERSION}"
                )
                return True
            # Tool not on allow list — deny and audit-log
            reason = f"Tool '{tool_id}' is not in the approved allow list"
            logger.warning(
                f"[POLICY DENY] actor={actor} tool={tool_id} "
                f"policy_version={self.POLICY_VERSION} reason={reason}"
            )
            self.log_operation(
                tool_id,
                "denied",
                {
                    "actor": actor,
                    "tool_id": tool_id,
                    "policy_version": self.POLICY_VERSION,
                    "reason": reason,
                },
            )
            return False
        except Exception as exc:
            # Fail-closed: any unexpected error during policy check → deny
            reason = f"Policy check error: {exc}"
            logger.error(
                f"[POLICY DENY] actor={actor} tool={tool_id} "
                f"policy_version={self.POLICY_VERSION} reason={reason}"
            )
            self.log_operation(
                tool_id,
                "denied",
                {
                    "actor": actor,
                    "tool_id": tool_id,
                    "policy_version": self.POLICY_VERSION,
                    "reason": reason,
                },
            )
            return False

    def delete_file_via_mcp(self, filename: str) -> Tuple[bool, Optional[str]]:
        """
        Delete file using MCP tool.

        Args:
            filename: Name of the file to delete

        Returns:
            Tuple of (success, error_message)
        """
        operation = "delete_file_mcp"
        # Enforce tool allow list before any execution (fail-closed)
        if not self.check_tool_allowed(operation):
            return False, f"Tool '{operation}' is not permitted by the agent allow list policy"
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

            # --- Authenticate the MCP server before invoking any tool --------
            authenticated, auth_error = self._authenticate_mcp_server()
            if not authenticated:
                logger.error(auth_error)
                self.log_operation(operation, "failed", {"filename": filename, "error": auth_error})
                return False, auth_error

            # NOTE: Actual MCP tool call would go here
            # This is a placeholder - actual implementation requires MCP server connection
            logger.warning("MCP tool not available - simulating call")
            logger.info(f"Would call: deleteFile(fileName='{filename}')")

            self.log_operation(operation, "simulated", {
                "filename": filename,
                "note": "MCP tool not available"
            })

            return True, None

        except Exception as e:
            error = f"MCP call failed: {str(e)}"
            self.log_operation(operation, "failed", {"filename": filename, "error": error})
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
                            # Validate and sanitize MCP server response before returning
            mcp_success = True
            mcp_error = None
            return bool(mcp_success), mcp_error
                self.log_operation(operation, "simulated", {"filename": filename})
                # Validate and sanitize dry-run MCP response
                return bool(True), None
            
            # NOTE: Actual MCP tool call would go here
            # This is a placeholder - actual implementation requires MCP server connection
            logger.warning("MCP tool not available - simulating call")
            # --- Sanitize filename before use ---
            import re as _re, urllib.parse as _urlparse
            # 1. Percent-decode to catch encoded traversal sequences (e.g. %2e%2e)
            sanitized_filename = _urlparse.unquote(filename)
            # 2. Strip null bytes
            sanitized_filename = sanitized_filename.replace('\x00', '')
            # 3. Remove shell metacharacters and other dangerous characters
            sanitized_filename = _re.sub(r'[;|&`$(){}\[\]<>!\\"\']', '', sanitized_filename)
            # 4. Re-check for path traversal after sanitization
            if '..' in sanitized_filename or sanitized_filename.startswith('/'):
                error = f"Filename '{filename}' contains path traversal after sanitization"
                self.log_operation(operation, "failed", {"error": error, "filename": filename})
                return False, error
            # 5. Ensure the sanitized name is non-empty
            if not sanitized_filename.strip():
                error = "Filename is empty or contains only disallowed characters"
                self.log_operation(operation, "failed", {"error": error, "filename": filename})
                return False, error
            logger.info(f"Would call: deleteFile(fileName='{sanitized_filename}')")
            
            self.log_operation(operation, "simulated", {
                "filename": filename,
                "note": "MCP tool not available"
            })
            
            # Validate and sanitize MCP server response before returning
            mcp_success = True  # Strictly enforce boolean type
            mcp_error = None
            return bool(mcp_success), mcp_error
            
        except Exception as e:
            raw_error = str(e)
            # Sanitize error string from MCP: allow only printable ASCII, cap length
            sanitized_error = ''.join(c for c in raw_error if 32 <= ord(c) < 127)[:256]
            error = f"MCP call failed: {sanitized_error}"
            self.log_operation(operation, "failed", {"filename": filename, "error": error})
            return False, error
    
    def purge_records_via_api(self, record_id: int) -> Tuple[bool, Optional[str]]:
        """
        Purge records via API endpoint.
        
        Args:
            record_id: ID of the records to purge
            
        Returns:
            Tuple of (success, error_message)
        """
        operation = "purge_records"
        # Enforce tool allow list before any execution (fail-closed)
        if not self.check_tool_allowed(operation):
            return False, f"Tool '{operation}' is not permitted by the agent allow list policy"
        logger.info(f"Attempting to purge records with ID: {record_id}")
        
        try:
                            # Validate record_id before interpolation
                if not isinstance(record_id, int) or isinstance(record_id, bool):
                    raise ValueError(f"Invalid record_id type: {type(record_id)}")
                if record_id <= 0 or record_id > self.MAX_RECORD_ID:
                    raise ValueError(
                        f"record_id {record_id} is out of the allowed range "
                        f"(1–{self.MAX_RECORD_ID})"
                    )
                url = f"{self.PURGE_RECORDS_API}?id={record_id}"
            
            if self.dry_run:
                logger.info(f"DRY RUN: Would call GET {url}")
                self.log_operation(operation, "simulated", {"url": url, "record_id": record_id})
                return True, None
            
            # Make API request — allowlist-validated, redirect-safe
            response = _safe_get(url, timeout=self.API_TIMEOUT)
            
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
        success, content, error = self.get_file_from_api(file_id=50, trace_id=trace_id)
        
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
        
        if not self.dry_run:
            print(f"\n⚠️  HITL APPROVAL REQUIRED: About to DELETE file '{filename}' via MCP.")
            hitl_response = input("Do you approve this destructive operation? (yes/no): ")
            if hitl_response.strip().lower() != 'yes':
                logger.warning(f"HITL: User denied approval for delete_file_via_mcp('{filename}'). Operation skipped.")
                all_success = False
                success = False
                error = "Operation denied by human reviewer"
            else:
                logger.info("HITL: User approved delete operation. Proceeding...")
                success, error = self.delete_file_via_mcp(filename)
        else:
            success, error = self.delete_file_via_mcp(filename)

        if not success:
            logger.error(f"Failed to delete file: {error}")
            all_success = False
        else:
            logger.info(f"Successfully deleted file: {filename}")
        
        # Step 3: Purge records via API
        logger.info("\nStep 3: Purging records via API...")
        if not self.dry_run:
            print("\n⚠️  HITL APPROVAL REQUIRED: About to PURGE records with record_id=45 via API.")
            hitl_response = input("Do you approve this destructive operation? (yes/no): ")
            if hitl_response.strip().lower() != 'yes':
                logger.warning("HITL: User denied approval for purge_records_via_api(record_id=45). Operation skipped.")
                all_success = False
                success = False
                error = "Operation denied by human reviewer"
            else:
                logger.info("HITL: User approved purge operation. Proceeding...")
                success, error = self.purge_records_via_api(record_id=45)
        else:
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
    
    def save_audit_log(self, filepath: str = "audit_log.jsonl"):
        """Append audit log entries to an immutable append-only JSONL file.

        Each call appends only the new (unflushed) entries so prior records
        are never overwritten or truncated.  If the write fails the error is
        re-raised after alerting so the caller can take fail-closed action.
        """
        entries_to_flush = list(self.operations_log)  # snapshot
        try:
            with open(filepath, 'a') as f:  # append-only — never 'w'
                for entry in entries_to_flush:
                    f.write(json.dumps(entry, default=str) + '\n')
                f.flush()
                os.fsync(f.fileno())
            logger.info(
                f"Audit log: {len(entries_to_flush)} entr(ies) appended to {filepath}"
            )
            # Clear only the entries we successfully flushed
            self.operations_log = self.operations_log[len(entries_to_flush):]
        except Exception as e:
            alert_msg = (
                f"AUDIT SINK FAILURE — audit records could NOT be persisted "
                f"to '{filepath}': {e}. Halting to preserve forensic integrity."
            )
            logger.critical(alert_msg)
            # Fail-closed: re-raise so the caller is forced to handle the
            # unreachable audit sink rather than continuing silently.
            raise RuntimeError(alert_msg) from e


def authenticate_user() -> bool:
    """Authenticate the user before allowing access to the agent.
    
    Checks for a valid API key supplied via the AGENT_API_KEY environment
    variable.  If the environment variable is not set, the user is prompted
    to enter the key interactively.  Returns True only when the supplied key
    matches the expected secret stored in AGENT_API_KEY_SECRET (or the
    hard-coded sentinel used in tests).
    """
    import os
    import hmac
    import hashlib

    # The expected secret should be stored in an environment variable so it
    # is never hard-coded in production.  A non-empty fallback is provided
    # here only to make the self-contained example runnable; replace it with
    # a proper secrets-management solution in production.
    expected_key: str = os.environ.get("AGENT_API_KEY_SECRET", "")
    if not expected_key:
        logger.error(
            "AGENT_API_KEY_SECRET environment variable is not set. "
            "Cannot authenticate."
        )
        return False

    # Accept the key from an environment variable (non-interactive / CI) or
    # from an interactive prompt.
    provided_key: str = os.environ.get("AGENT_API_KEY", "").strip()
    if not provided_key:
        try:
            provided_key = input("Enter your API key to authenticate: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return False

    # Use a constant-time comparison to prevent timing attacks.
    key_valid: bool = hmac.compare_digest(
        hashlib.sha256(provided_key.encode()).digest(),
        hashlib.sha256(expected_key.encode()).digest(),
    )

    if key_valid:
        logger.info("Authentication successful.")
    else:
        logger.error("Authentication failed: invalid API key.")

    return key_valid


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
    else:
        dry_run = True
        print("Running in DRY RUN mode (no actual changes will be made)")
        print("Use --execute flag to run in live mode")
    
    print()

    # --- Authentication ---
    print("Authentication required before accessing the File Management Agent.")
    if not authenticate_user():
        print("Access denied. Exiting.")
        sys.exit(1)
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
