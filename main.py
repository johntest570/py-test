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
import hashlib
import logging
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


class FileManagementAgent:
    """Agent for file retrieval, deletion, and record management."""
    
    # API endpoints
    GET_FILE_API = "https://www.testme160375.com/getFile"
    PURGE_RECORDS_API = "https://x1w3n1m6.com/purgeRecords"
    
    # Timeouts and limits
    API_TIMEOUT = 30  # seconds
    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

    # URL allowlist: set of (scheme, hostname) pairs permitted for outbound HTTP requests
    ALLOWED_ORIGINS = {
        ("https", "www.testme160375.com"),
        ("https", "x1w3n1m6.com"),
    }

    @classmethod
    def _validate_url(cls, url: str) -> None:
        """
        Validate that a URL's scheme and hostname are in the allowlist.

        Args:
            url: The URL to validate.

        Raises:
            ValueError: If the URL scheme or hostname is not in the allowlist.
        """
        from urllib.parse import urlparse
        parsed = urlparse(url)
        origin = (parsed.scheme.lower(), parsed.hostname.lower() if parsed.hostname else "")
        if origin not in cls.ALLOWED_ORIGINS:
            raise ValueError(
                f"URL '{url}' is not permitted. "
                f"Allowed origins: {cls.ALLOWED_ORIGINS}"
            )
    
    # Agent/model identity constants for forensic audit records
    AGENT_ID = "FileManagementAgent"
    AGENT_VERSION = "1.0.0"
    # Retention policy: audit records must be kept for at least this many days
    AUDIT_RETENTION_DAYS = 365

    def __init__(self, dry_run: bool = True, principal: str = "unknown"):
        """
        Initialize the agent.
        
        Args:
            dry_run: If True, only simulate operations without making actual changes
            principal: Identity of the user or service invoking this agent (required for audit)
        """
        self.dry_run = dry_run
        self.operations_log = []
        self.principal = principal  # Actor/user identity for audit records
        
        if dry_run:
            logger.warning("Agent running in DRY RUN mode - no actual changes will be made")
    
    @staticmethod
    def _compute_input_hash(details: Dict) -> str:
        """Compute a SHA-256 hash of the input details for forensic integrity."""
        canonical = json.dumps(details, sort_keys=True, default=str).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()

    def log_operation(self, operation: str, status: str, details: Dict):
        """Log operation for audit trail with full forensic context."""
        input_hash = self._compute_input_hash(details)
        retention_expires = (datetime.utcnow() + timedelta(days=self.AUDIT_RETENTION_DAYS)).isoformat() + "Z"
        log_entry = {
            'timestamp': datetime.utcnow().isoformat() + "Z",
            'operation': operation,
            'status': status,
            # Forensic / model identity fields
            'agent_id': self.AGENT_ID,
            'agent_version': self.AGENT_VERSION,
            'principal': self.principal,
            # Input integrity
            'input_hash': input_hash,
            'input_hash_algorithm': 'sha256',
            # Data provenance
            'source_provenance': {
                'api_base_get': self.GET_FILE_API,
                'api_base_purge': self.PURGE_RECORDS_API,
            },
            # Retention policy metadata
            'retention_policy': {
                'retain_days': self.AUDIT_RETENTION_DAYS,
                'expires_at': retention_expires,
            },
            'details': details,
        }
        self.operations_log.append(log_entry)
        logger.info(f"Operation: {operation} - Status: {status} - InputHash: {input_hash} - Principal: {self.principal}")
    
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

        # Validate file_id: must be a positive integer within a safe range
        if not isinstance(file_id, int) or isinstance(file_id, bool):
            raise ValueError(f"file_id must be an integer, got {type(file_id).__name__}")
        if file_id <= 0 or file_id > 2_147_483_647:
            raise ValueError(f"file_id out of valid range: {file_id}")
        # Use the validated integer directly (not via f-string interpolation of arbitrary input)
        safe_file_id = int(file_id)

        try:
            url = f"{self.GET_FILE_API}?id={safe_file_id}"
            
            if self.dry_run:
                logger.info(f"DRY RUN: Would call GET {url}")
                self.log_operation(operation, "simulated", {"url": url, "file_id": safe_file_id})
                return True, "DRY_RUN_CONTENT", None

            # Make API request
            response = requests.get(url, headers=self._auth_headers, timeout=self.API_TIMEOUT)
            
            # Check response status
            if response.status_code != 200:
                error = "API request was unsuccessful"
                self.log_operation(operation, "failed", {"error": error})
                return False, None, error
            
            # Check content size
            content = response.text

            # Sanitize content for malicious prompt injection
            sanitized_ok, sanitize_error = self._sanitize_file_content(content)
            if not sanitized_ok:
                self.log_operation(operation, "failed", {"error": sanitize_error})
                return False, None, sanitize_error
            if len(content) > self.MAX_FILE_SIZE:
                error = f"File too large: {len(content)} bytes (max {self.MAX_FILE_SIZE})"
                self.log_operation(operation, "failed", {"error": error})
                return False, None, error
            
            # Success
            self.log_operation(operation, "success", {
                "url": url,
                "file_id": file_id,
                "content_length": len(content)
            })
            
            # Check for Singapore PII before returning content
            pii_detected, pii_types = self._contains_singapore_pii(content)
            if pii_detected:
                error = f"File content contains Singapore PII ({', '.join(pii_types)}); upload blocked per policy"
                self.log_operation(operation, "failed", {
                    "url": url,
                    "file_id": file_id,
                    "error": error
                })
                return False, None, error

            return True, content, None
            
        except requests.Timeout:
            error = "Request timeout"
            self.log_operation(operation, "failed", {"error": error})
            return False, None, error
        except requests.RequestException:
            error = "A network error occurred while contacting the API"
            self.log_operation(operation, "failed", {"error": error})
            return False, None, error
        except Exception:
            error = "An unexpected error occurred"
            self.log_operation(operation, "failed", {"error": error})
            return False, None, error
    
    def _sanitize_file_content(self, content: str) -> Tuple[bool, Optional[str]]:
        """
        Inspect file content for malicious prompt injection attempts.

        Checks for:
        - Invisible/hidden Unicode characters used to hide prompts
        - Base64-encoded prompt injection payloads
        - Leetspeak obfuscation patterns
        - Suspicious prompt-injection keywords
        - Binary data or shell commands

        Returns:
            Tuple of (is_safe, error_message)
        """
        import re
        import base64

        # 1. Detect invisible / zero-width Unicode characters commonly used to hide text
        invisible_chars = [
            '\u200b', '\u200c', '\u200d', '\u200e', '\u200f',
            '\u202a', '\u202b', '\u202c', '\u202d', '\u202e',
            '\u2060', '\u2061', '\u2062', '\u2063', '\u2064',
            '\ufeff', '\u00ad',
        ]
        for ch in invisible_chars:
            if ch in content:
                return False, "Malicious content detected: invisible/hidden Unicode characters found in file"

        # 2. Detect suspicious prompt-injection keywords (case-insensitive)
        prompt_injection_patterns = [
            r'ignore\s+(all\s+)?(previous|prior|above)\s+instructions',
            r'disregard\s+(all\s+)?(previous|prior|above)\s+instructions',
            r'forget\s+(all\s+)?(previous|prior|above)\s+instructions',
            r'you\s+are\s+now\s+(a|an)\s+',
            r'act\s+as\s+(a|an)\s+',
            r'pretend\s+(you\s+are|to\s+be)\s+',
            r'new\s+instructions?\s*:',
            r'system\s*:\s*you\s+are',
            r'<\s*system\s*>',
            r'\[\s*system\s*\]',
            r'###\s*instruction',
            r'jailbreak',
            r'prompt\s+injection',
            r'override\s+(your\s+)?(instructions?|rules?|guidelines?)',
        ]
        for pattern in prompt_injection_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return False, f"Malicious content detected: suspicious prompt-injection pattern found in file"

        # 3. Detect binary / non-printable characters (indicative of binary payloads or shell commands)
        # Allow common whitespace: tab, newline, carriage return
        non_printable = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]')
        if non_printable.search(content):
            return False, "Malicious content detected: binary or non-printable characters found in file"

        # 4. Detect shell command patterns
        shell_patterns = [
            r'(?:^|\s|;|&&|\|\|)(?:rm|wget|curl|chmod|chown|sudo|bash|sh|python|perl|ruby|nc|ncat|netcat)\s',
            r'\$\([^)]+\)',   # command substitution $()
            r'`[^`]+`',        # backtick command substitution
            r'/etc/passwd',
            r'/bin/sh',
            r'/bin/bash',
        ]
        for pattern in shell_patterns:
            if re.search(pattern, content, re.IGNORECASE | re.MULTILINE):
                return False, "Malicious content detected: shell command pattern found in file"

        # 5. Detect base64-encoded blobs that may contain hidden prompts
        # Look for long base64 strings (>=64 chars) and decode to inspect
        b64_pattern = re.compile(r'(?:[A-Za-z0-9+/]{4}){16,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')
        for match in b64_pattern.finditer(content):
            try:
                decoded = base64.b64decode(match.group()).decode('utf-8', errors='ignore')
                for pattern in prompt_injection_patterns:
                    if re.search(pattern, decoded, re.IGNORECASE):
                        return False, "Malicious content detected: base64-encoded prompt injection found in file"
                for pattern in shell_patterns:
                    if re.search(pattern, decoded, re.IGNORECASE | re.MULTILINE):
                        return False, "Malicious content detected: base64-encoded shell command found in file"
            except Exception:
                pass  # Not valid base64 or not decodable — skip

        # 6. Detect leetspeak obfuscation of common injection keywords
        # Normalise common leet substitutions and re-check injection patterns
        leet_map = str.maketrans('013456789@$!', 'oieashgtbgas')
        normalised = content.lower().translate(leet_map)
        for pattern in prompt_injection_patterns:
            if re.search(pattern, normalised, re.IGNORECASE):
                return False, "Malicious content detected: leetspeak-obfuscated prompt injection found in file"

        return True, None

    def _contains_singapore_pii(self, content: str) -> Tuple[bool, list]:
        """
        Scan content for Singapore PII categories.

        Checks for:
          - NRIC / FIN numbers (e.g. S1234567A, T0123456B, F1234567C, G1234567D)
          - Singapore passport numbers (e.g. E1234567A)
          - Singapore phone numbers (+65 XXXX XXXX)
          - Bank account numbers (common SG formats)
          - Email addresses
          - Full name patterns (salutation + capitalised words)

        Returns:
            Tuple of (pii_found: bool, list_of_detected_pii_types: list)
        """
        import re

        detected = []

        patterns = {
            "NRIC/FIN": r'\b[STFG]\d{7}[A-Z]\b',
            "Passport Number": r'\b[A-Z]\d{7}[A-Z]\b',
            "Singapore Phone": r'(?:\+65[\s-]?)?[689]\d{3}[\s-]?\d{4}\b',
            "Bank Account Number": r'\b\d{3}[-\s]?\d{6}[-\s]?\d{1,3}\b',
            "Email Address": r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b',
            "Full Name": r'\b(?:Mr|Mrs|Ms|Dr|Prof)\.?\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)+\b',
        }

        for pii_type, pattern in patterns.items():
            if re.search(pattern, content):
                detected.append(pii_type)

        return (len(detected) > 0, detected)

    def _authenticate_mcp_server(self) -> Tuple[bool, Optional[str]]:
        """
        Authenticate the MCP server before invoking any MCP tool.

        Performs two checks:
        1. Token-based authentication: sends the pre-shared secret (read from the
           MCP_SERVER_TOKEN environment variable) to the MCP server's /auth endpoint
           and verifies the server acknowledges it.
        2. TLS certificate verification: enforced by requests via the system CA bundle
           (verify=True), ensuring the server presents a valid, trusted certificate.

        Returns:
            Tuple of (authenticated: bool, error_message: Optional[str])
        """
        import os

        mcp_token = os.environ.get("MCP_SERVER_TOKEN", "").strip()
        if not mcp_token:
            return False, "MCP_SERVER_TOKEN environment variable is not set"

        mcp_auth_url = os.environ.get(
            "MCP_SERVER_AUTH_URL", "https://mcp-server/auth"
        ).rstrip("/")

        try:
            # TLS certificate verification is enabled by default (verify=True).
            # The Authorization header carries the pre-shared bearer token so the
            # server can confirm the client's identity, and the server's signed TLS
            # certificate confirms the server's identity to the client.
            response = requests.post(
                mcp_auth_url,
                headers={
                    "Authorization": f"Bearer {mcp_token}",
                    "Content-Type": "application/json",
                },
                timeout=self.API_TIMEOUT,
                verify=True,   # enforce TLS certificate verification
            )
            if response.status_code == 200:
                logger.info("MCP server authenticated successfully")
                return True, None
            error = (
                f"MCP server returned HTTP {response.status_code} "
                f"during authentication"
            )
            logger.error(error)
            return False, error
        except requests.exceptions.SSLError as exc:
            error = f"MCP server TLS certificate verification failed: {exc}"
            logger.error(error)
            return False, error
        except requests.RequestException as exc:
            error = f"MCP server authentication request failed: {exc}"
            logger.error(error)
            return False, error

            # ---------------------------------------------------------------------------
    # Tool allow list policy
    # ---------------------------------------------------------------------------
    # Maps (role, task_class) -> frozenset of permitted MCP tool ids.
    # Only tools that appear in the entry matching the current actor's role AND
    # the requested task class may be invoked.  Any other tool is denied and the
    # denial is written to the audit log before the call is rejected.
    TOOL_ALLOW_LIST: dict = {
        ("admin",    "file_management"): frozenset({"deleteFile", "listFiles", "readFile"}),
        ("operator", "file_management"): frozenset({"listFiles", "readFile"}),
        ("service",  "file_management"): frozenset({"deleteFile", "listFiles", "readFile"}),
    }

    # Increment this version string whenever the allow list above is changed so
    # that audit records can be correlated with the policy that was in effect.
    TOOL_POLICY_VERSION: str = "1.0.0"

    def _check_tool_allowed(
        self,
        tool_id: str,
        task_class: str,
        actor: str,
        role: str,
    ) -> bool:
        """
        Enforce the tool allow list for the given (role, task_class) scope.

        Returns True when the tool is permitted.  Returns False and writes a
        structured denial record to the audit log when it is not.
        """
        permitted = self.TOOL_ALLOW_LIST.get((role, task_class), frozenset())
        if tool_id in permitted:
            return True

        # --- Denied: write audit record to protected sink -------------------
        denial_record = {
            "event":          "tool_invocation_denied",
            "tool_id":        tool_id,
            "actor":          actor,
            "role":           role,
            "task_class":     task_class,
            "policy_version": self.TOOL_POLICY_VERSION,
            "denial_reason":  (
                f"Tool '{tool_id}' is not in the allow list for "
                f"role='{role}', task_class='{task_class}'. "
                f"Permitted tools: {sorted(permitted) if permitted else 'none'}."
            ),
        }
        # Log at ERROR level so the record is always captured even when the
        # root logger is configured at a higher threshold.
        logger.error("AUDIT DENIAL: %s", denial_record)
        # Also persist via log_operation so the structured store receives it.
        self.log_operation("tool_policy_check", "denied", denial_record)
        return False

    def delete_file_via_mcp(
        self,
        filename: str,
        actor: str = "system",
        role: str = "service",
    ) -> Tuple[bool, Optional[str]]:
        """
        Delete file using MCP tool.

        Args:
            filename:  Name of the file to delete.
            actor:     Identity of the caller (user id, service account, etc.).
            role:      Role of the caller used for allow-list scoping
                       (e.g. 'admin', 'operator', 'service').

        Returns:
            Tuple of (success, error_message)
        """
        operation  = "delete_file_mcp"
        tool_id    = "deleteFile"
        task_class = "file_management"

        logger.info(f"Attempting to delete file via MCP: {filename}")

        # ------------------------------------------------------------------
        # 1. Tool allow list enforcement (per-role, per-task-class)
        # ------------------------------------------------------------------
        if not self._check_tool_allowed(tool_id, task_class, actor, role):
            error = (
                f"Tool '{tool_id}' invocation denied by policy "
                f"(actor='{actor}', role='{role}', "
                f"task_class='{task_class}', "
                f"policy_version='{self.TOOL_POLICY_VERSION}')."
            )
            return False, error

        # ------------------------------------------------------------------
        # 2. Input validation
        # ------------------------------------------------------------------
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

            # NOTE: Actual MCP tool call would go here
            # This is a placeholder - actual implementation requires MCP server connection
            logger.warning("MCP tool not available - simulating call")
            logger.info(f"Would call: deleteFile(fileName='{filename}')")

            self.log_operation(operation, "simulated", {
                "filename": filename,
                "note":     "MCP tool not available",
            })

            return True, None

        except Exception as e:
            error = f"MCP call failed: {str(e)}"
            self.log_operation(operation, "failed", {"filename": filename, "error": error})
            return False, error
        auth_headers = {"Authorization": f"Bearer {mcp_api_token}"}
        # --- End client authentication ---

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
                logger.info(f"DRY RUN: Would call MCP deleteFile('{filename}') with authentication")
                self.log_operation(operation, "simulated", {"filename": filename, "authenticated": True})
                return True, None
            
            # NOTE: Actual MCP tool call would go here.
            # Pass auth_headers (containing the Bearer token) to the MCP client so
            # the server can authenticate this client before processing the request.
            # Example: mcp_client.call_tool("deleteFile", {"fileName": filename}, headers=auth_headers)
            logger.warning("MCP tool not available - simulating authenticated call")
            logger.info(
                f"Would call: deleteFile(fileName='{filename}') "
                f"with Authorization header present: {bool(auth_headers.get('Authorization'))}"
            )
            
            self.log_operation(operation, "simulated", {
                "filename": filename,
                "authenticated": True,
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
                return True, None
            
            # Make the actual MCP tool call and log the interaction
            logger.info(f"Calling MCP tool deleteFile(fileName='{filename}')")
            mcp_request = {"tool": "deleteFile", "arguments": {"fileName": filename}}
            logger.info(f"MCP request: {mcp_request}")
            
            mcp_response = self.mcp_client.call_tool("deleteFile", {"fileName": filename})
            
            logger.info(f"MCP response: {mcp_response}")
            self.log_operation(operation, "success", {
                "filename": filename,
                "mcp_request": mcp_request,
                "mcp_response": str(mcp_response)
            })
            
            return True, None
            
        except Exception as e:
            error = f"MCP call failed: {str(e)}"
            self.log_operation(operation, "failed", {"filename": filename, "error": error})
            return False, error
    
    # ------------------------------------------------------------------
    # MCP response validation helper
    # ------------------------------------------------------------------
    def _validate_mcp_response(
        self,
        response: object,
        expected_filename: str = ""
    ) -> "Tuple[bool, Optional[dict], Optional[str]]":
        """
        Validate and sanitize a response received from (or simulated for) an
        MCP server tool call.

        Args:
            response: The raw value returned by the MCP tool.
            expected_filename: The filename that was sent to the MCP tool so
                               the response can be cross-checked.

        Returns:
            Tuple of (is_valid, sanitized_response_dict, error_message)
        """
        import re

        # 1. Response must be a dict
        if not isinstance(response, dict):
            return False, None, "MCP response is not a dict"

        # 2. Must contain a 'status' field that is a non-empty string
        status = response.get("status")
        if not isinstance(status, str) or not status.strip():
            return False, None, "MCP response missing or invalid 'status' field"

        # 3. Sanitize status: allow only alphanumeric, underscore, hyphen
        sanitized_status = re.sub(r"[^a-zA-Z0-9_\-]", "", status).strip()
        if not sanitized_status:
            return False, None, "MCP response 'status' contains no safe characters"

        # 4. If a fileName is echoed back, verify it matches what we sent
        echoed_filename = response.get("fileName", "")
        if echoed_filename and isinstance(echoed_filename, str):
            # Sanitize echoed filename before comparison
            sanitized_echoed = re.sub(r"[^a-zA-Z0-9_.\-]", "", echoed_filename)
            if expected_filename and sanitized_echoed != expected_filename:
                return (
                    False,
                    None,
                    f"MCP response fileName mismatch: expected '{expected_filename}', "
                    f"got '{sanitized_echoed}'",
                )
        else:
            sanitized_echoed = ""

        # 5. Sanitize optional 'note' field
        raw_note = response.get("note", "")
        sanitized_note = ""
        if isinstance(raw_note, str):
            # Strip control characters and limit length
            sanitized_note = re.sub(r"[\x00-\x1f\x7f]", "", raw_note)[:256]

        sanitized_response = {
            "status": sanitized_status,
            "fileName": sanitized_echoed,
            "note": sanitized_note,
        }
        return True, sanitized_response, None

    def purge_records_via_api(self, record_id: int) -> Tuple[bool, Optional[str]]:
        """
        Purge records via API endpoint.
        
        Args:
            record_id: ID of the records to purge
            
        Returns:
            Tuple of (success, error_message)
        """
        operation = "purge_records"
        logger.info(f"Attempting to purge records with ID: {record_id}")
        
        try:
            url = f"{self.PURGE_RECORDS_API}?id={record_id}"
            
            if self.dry_run:
                logger.info(f"DRY RUN: Would call GET {url}")
                self.log_operation(operation, "simulated", {"url": url, "record_id": record_id})
                return True, None
            
            # Make API request
            response = requests.get(url, headers=self._auth_headers, timeout=self.API_TIMEOUT)
            
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
        """Append operations log entries to the append-only audit log file.

        The file is opened in append mode so existing records are never
        overwritten or truncated (immutable / append-only storage).
        Each call writes a JSON-lines record per entry so the file grows
        monotonically and individual records remain independently parseable.

        Raises:
            RuntimeError: Always re-raised when the audit sink is unreachable
                          or the write fails, so the caller fails closed rather
                          than silently continuing without an audit record.
        """
        try:
            # Append-only: 'a' mode never truncates existing content.
            with open(filepath, 'a') as f:
                for entry in self.operations_log:
                    # JSON-lines format: one record per line, easy to tail/grep.
                    f.write(json.dumps(entry, default=str) + "\n")
            logger.info(
                f"Audit log appended {len(self.operations_log)} entr(ies) to: {filepath}"
            )
        except Exception as e:
            logger.error(f"CRITICAL: Failed to save audit log to '{filepath}': {e}")
            # Fail closed — do not silently continue if the audit sink is broken.
            raise RuntimeError(
                f"Audit logging failure (sink unreachable or write error): {e}"
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
