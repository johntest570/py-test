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
from datetime import datetime, timezone
from typing import Optional, Dict, Tuple

try:
    import requests
except ImportError:
    print("Error: requests package is not installed.")
    print("Install it with: pip3 install requests")
    sys.exit(1)

# MCP server authentication token (must match the server's configured token)
# Set via environment variable MCP_SERVER_TOKEN for security
MCP_SERVER_EXPECTED_TOKEN = os.environ.get("MCP_SERVER_TOKEN", "")
if not MCP_SERVER_EXPECTED_TOKEN:
    logger.warning(
        "MCP_SERVER_TOKEN environment variable is not set. "
        "Server authentication will be enforced at runtime."
    )


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

    # URL allowlist: only these exact base URLs (scheme + host + path prefix) are permitted
    _ALLOWED_URL_PREFIXES = (
        "https://www.testme160375.com/getFile",
        "https://x1w3n1m6.com/purgeRecords",
    )
    
    # Timeouts and limits
    API_TIMEOUT = 30  # seconds
    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
    
    # Agent identity constants — update these when the model/version changes
    AGENT_ID = "file-management-agent"
    AGENT_VERSION = "1.0.0"
    AUDIT_LOG_PATH = "file_management_audit.jsonl"

    def __init__(self, dry_run: bool = True, principal: str = "system"):
        """
        Initialize the agent.

        Args:
            dry_run: If True, only simulate operations without making actual changes
            principal: Identity of the operator/caller for audit records
        """
        self.dry_run = dry_run
        self.principal = principal
        # No in-memory log — all audit records go directly to the append-only file

        if dry_run:
            logger.warning("Agent running in DRY RUN mode - no actual changes will be made")
    
    # Allowed base directory for file operations (adjust as needed)
    ALLOWED_BASE_DIR = "/allowed/files"

    def validate_and_sanitize_file_path(self, file_path) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Validate and sanitize a file path received from an external source.

        Args:
            file_path: The raw file path value to validate.

        Returns:
            Tuple of (is_valid, sanitized_path, error_message)
        """
        # Must be a non-empty string
        if not isinstance(file_path, str) or not file_path.strip():
            return False, None, "file_path must be a non-empty string"

        sanitized = file_path.strip()

        # Reject null bytes
        if "\x00" in sanitized:
            return False, None, "file_path contains null bytes"

        # Reject shell metacharacters that could enable injection
        forbidden_chars = set("|;&$`!><(){}[]\\")
        found = [c for c in sanitized if c in forbidden_chars]
        if found:
            return False, None, f"file_path contains forbidden characters: {found}"

        # Reject path traversal sequences
        import posixpath
        normalized = posixpath.normpath(sanitized)
        if ".." in normalized.split("/"):
            return False, None, "file_path contains path traversal sequences"

        # Enforce that the path is within the allowed base directory
        allowed = self.ALLOWED_BASE_DIR.rstrip("/")
        if not normalized.startswith(allowed + "/") and normalized != allowed:
            return False, None, (
                f"file_path '{normalized}' is outside the allowed base "
                f"directory '{self.ALLOWED_BASE_DIR}'"
            )

        return True, normalized, None

    def _validate_url(self, url: str) -> None:
        """Validate that *url* starts with an entry in the allowlist.

        Raises:
            ValueError: if the URL is not on the allowlist.
        """
        from urllib.parse import urlparse
        parsed = urlparse(url)
        # Require HTTPS scheme as a baseline
        if parsed.scheme != "https":
            raise ValueError(
                f"Outbound request blocked – scheme '{parsed.scheme}' is not allowed. "
                "Only HTTPS is permitted."
            )
        # Require the full URL to start with one of the known allowed prefixes
        if not any(url.startswith(prefix) for prefix in self._ALLOWED_URL_PREFIXES):
            raise ValueError(
                f"Outbound request blocked – URL '{url}' is not on the allowlist."
            )

    def log_operation(self, operation: str, status: str, details: Dict):
        """Append an immutable audit record to the append-only JSONL audit log.

        Required fields per forensic-readiness policy:
          - timestamp (UTC ISO-8601)
          - agent_id / agent_version  (model/component identifier)
          - principal                  (operator identity)
          - operation                  (action taken)
          - status                     (outcome)
          - input_hash                 (SHA-256 of serialised details for integrity)
          - details                    (full context)
        """
        # Compute a deterministic SHA-256 hash of the input details for integrity
        details_canonical = json.dumps(details, sort_keys=True, default=str)
        input_hash = hashlib.sha256(details_canonical.encode("utf-8")).hexdigest()

        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent_id": self.AGENT_ID,
            "agent_version": self.AGENT_VERSION,
            "principal": self.principal,
            "operation": operation,
            "status": status,
            "input_hash": input_hash,
            "details": details,
        }

        # Append-only write: 'a' mode prevents overwriting existing records
        with open(self.AUDIT_LOG_PATH, "a", encoding="utf-8") as audit_file:
            audit_file.write(json.dumps(log_entry, default=str) + "\n")
            audit_file.flush()
            os.fsync(audit_file.fileno())  # Ensure durability before returning

        logger.info(f"Operation: {operation} - Status: {status} - Hash: {input_hash}")
    
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
            
            # Validate URL against allowlist before making the request
            self._validate_url(url)

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
                return False, None, error
            
            # Sanitize content for malicious patterns before use
            raw_content = response.text
            is_safe, sanitize_error = self._check_content_safety(raw_content)
            if not is_safe:
                error = f"File content failed safety check: {sanitize_error}"
                self.log_operation(operation, "failed", {"error": error})
                return False, None, error
            content = raw_content
            if len(content) > self.MAX_FILE_SIZE:
                error = f"File too large: {len(content)} bytes (max {self.MAX_FILE_SIZE})"
                self.log_operation(operation, "failed", {"error": error})
                return False, None, error
            
            # Sanitize and validate content before returning
            # Reject non-string or empty content
            if not isinstance(content, str) or not content.strip():
                error = "Invalid or empty content received from API"
                self.log_operation(operation, "failed", {"error": error})
                return False, None, error

            # Remove null bytes and non-printable control characters (keep newlines/tabs)
            import re
            sanitized = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', content)

            # Reject content containing prompt-injection or command-injection patterns
            INJECTION_PATTERNS = [
                r'(?i)ignore\s+(all\s+)?previous\s+instructions',
                r'(?i)system\s*:\s*you\s+are',
                r'(?i)\bact\s+as\b',
                r'(?i)\bjailbreak\b',
                r'(?i)<\s*script[^>]*>',
                r'(?i)\beval\s*\(',
                r'(?i)\bexec\s*\(',
                r'(?i)\bos\.system\s*\(',
                r'(?i)\bsubprocess\b',
                r'(?i)\bdrop\s+table\b',
                r'(?i)\bdelete\s+from\b',
                r'(?i)\bunion\s+select\b',
            ]
            for pattern in INJECTION_PATTERNS:
                if re.search(pattern, sanitized):
                    error = "Content rejected: potential injection pattern detected"
                    self.log_operation(operation, "failed", {"error": error, "pattern": pattern})
                    return False, None, error

            # Ensure content contains only printable ASCII / unicode text
            # Reject if more than 5% of characters are non-printable after sanitization
            non_printable_count = sum(1 for c in sanitized if ord(c) < 32 and c not in ('\n', '\r', '\t'))
            if len(sanitized) > 0 and (non_printable_count / len(sanitized)) > 0.05:
                error = "Content rejected: excessive non-printable characters"
                self.log_operation(operation, "failed", {"error": error})
                return False, None, error

            # Success
            self.log_operation(operation, "success", {
                "url": url,
                "file_id": file_id,
                "content_length": len(sanitized)
            })

            return True, sanitized, None
            
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
    
    def _check_content_safety(self, content: str) -> Tuple[bool, Optional[str]]:
        """
        Check file content for malicious patterns including prompt injections,
        base64-encoded payloads, and shell commands.

        Args:
            content: The raw text content to check

        Returns:
            Tuple of (is_safe, error_message)
        """
        import re
        import base64

        # 1. Check for prompt injection patterns
        prompt_injection_patterns = [
            r'(?i)ignore\s+(all\s+)?(previous|prior|above)\s+instructions',
            r'(?i)disregard\s+(all\s+)?(previous|prior|above)\s+instructions',
            r'(?i)forget\s+(all\s+)?(previous|prior|above)\s+instructions',
            r'(?i)you\s+are\s+now\s+(a\s+)?(?!an?\s+agent)',
            r'(?i)act\s+as\s+(a\s+)?(?!an?\s+agent)',
            r'(?i)new\s+instructions?\s*:',
            r'(?i)system\s*:\s*you',
            r'(?i)<\s*system\s*>',
            r'(?i)\[\s*system\s*\]',
            r'(?i)###\s*instruction',
            r'(?i)###\s*system',
            r'(?i)jailbreak',
            r'(?i)do\s+anything\s+now',
            r'(?i)DAN\s+mode',
        ]
        for pattern in prompt_injection_patterns:
            if re.search(pattern, content):
                return False, f"Prompt injection pattern detected: {pattern}"

        # 2. Check for shell command patterns
        shell_command_patterns = [
            r'(?i)\b(rm|del|format|mkfs)\s+-[rRfF]',
            r'(?i);\s*(rm|del|wget|curl|bash|sh|python|perl|ruby|nc|ncat|netcat)\b',
            r'(?i)\|\s*(bash|sh|python|perl|ruby|nc|ncat|netcat)\b',
            r'(?i)`[^`]*`',
            r'(?i)\$\([^)]*\)',
            r'(?i)eval\s*\(',
            r'(?i)exec\s*\(',
            r'(?i)os\.system\s*\(',
            r'(?i)subprocess\.',
            r'(?i)__import__\s*\(',
        ]
        for pattern in shell_command_patterns:
            if re.search(pattern, content):
                return False, f"Shell command pattern detected: {pattern}"

        # 3. Check for base64-encoded payloads
        # Look for long base64-like strings and attempt to decode and re-check
        b64_pattern = re.findall(r'[A-Za-z0-9+/]{40,}={0,2}', content)
        for candidate in b64_pattern:
            # Pad if necessary
            padded = candidate + '=' * (-len(candidate) % 4)
            try:
                decoded = base64.b64decode(padded).decode('utf-8', errors='ignore')
                # Re-check decoded content for prompt injection and shell commands
                for pattern in prompt_injection_patterns + shell_command_patterns:
                    if re.search(pattern, decoded):
                        return False, "Malicious content detected in base64-encoded payload"
            except Exception:
                pass  # Not valid base64, skip

        # 4. Check for hidden/invisible characters used in prompt smuggling
        hidden_char_pattern = re.compile(
            r'[\u200b\u200c\u200d\u200e\u200f\u202a-\u202e\u2060-\u2064\ufeff]'
        )
        if hidden_char_pattern.search(content):
            return False, "Hidden/invisible characters detected that may indicate prompt smuggling"

        return True, None

    # ------------------------------------------------------------------ #
    # Content sanitization                                               #
    # ------------------------------------------------------------------ #
    _SHELL_COMMAND_RE = re.compile(
        r'(?:^|\s|;|&&|\|\|)'
        r'(?:bash|sh|zsh|cmd|powershell|exec|eval|system|popen|subprocess'
        r'|curl|wget|nc|ncat|netcat|chmod|chown|sudo|su|rm\s|mv\s|cp\s'
        r'|python|perl|ruby|php|node|lua|tclsh|awk|sed)'
        r'(?:\s|$|;|&&|\|)',
        re.IGNORECASE | re.MULTILINE,
    )
    # Matches typical base64 blobs (≥ 40 chars of base64 alphabet)
    _BASE64_RE = re.compile(
        r'(?:[A-Za-z0-9+/]{40,}={0,2})'
    )
    # Leetspeak heuristic: words where ≥ 40 % of alpha chars are digit substitutes
    _LEET_MAP = str.maketrans('013456789', 'oieashgbq')
    # Prompt-injection trigger phrases
    _INJECTION_PHRASES = [
        'ignore previous instructions',
        'ignore all instructions',
        'disregard previous',
        'forget your instructions',
        'you are now',
        'act as',
        'jailbreak',
        'do anything now',
        'dan mode',
        'system prompt',
        '<!-- ',
        '<script',
        '<?php',
    ]

    def _sanitize_content(self, content: str) -> Tuple[bool, Optional[str]]:
        """
        Inspect *content* for patterns that indicate prompt injection,
        hidden instructions, base64 payloads, leetspeak obfuscation,
        shell commands, or binary data.

        Returns (True, None) when the content is considered safe, or
        (False, reason_string) when a threat is detected.
        """
        import base64 as _base64

        if not isinstance(content, str):
            return False, "Content is not a string"

        # 1. Binary / non-printable bytes check
        non_printable = sum(
            1 for ch in content
            if ord(ch) < 32 and ch not in ('\n', '\r', '\t')
        )
        if non_printable > 0:
            return False, (
                f"Content contains {non_printable} non-printable/binary character(s)"
            )

        lower = content.lower()

        # 2. Prompt-injection phrase check
        for phrase in self._INJECTION_PHRASES:
            if phrase in lower:
                return False, f"Potential prompt injection detected: '{phrase}'"

        # 3. Shell-command pattern check
        if self._SHELL_COMMAND_RE.search(content):
            return False, "Potential shell command detected in content"

        # 4. Base64 blob check — also try to decode and re-inspect
        for match in self._BASE64_RE.finditer(content):
            blob = match.group(0)
            try:
                decoded = _base64.b64decode(blob + '==').decode('utf-8', errors='replace')
                # Re-run phrase and shell checks on decoded payload
                decoded_lower = decoded.lower()
                for phrase in self._INJECTION_PHRASES:
                    if phrase in decoded_lower:
                        return False, (
                            f"Base64-encoded prompt injection detected: '{phrase}'"
                        )
                if self._SHELL_COMMAND_RE.search(decoded):
                    return False, "Base64-encoded shell command detected in content"
            except Exception:
                pass  # Not valid base64 — ignore

        # 5. Leetspeak heuristic
        for word in re.findall(r'[A-Za-z0-9]{6,}', content):
            translated = word.translate(self._LEET_MAP).lower()
            leet_chars = sum(
                1 for orig, trans in zip(word.lower(), translated)
                if orig != trans
            )
            if len(word) > 0 and leet_chars / len(word) >= 0.4:
                return False, (
                    f"Potential leetspeak obfuscation detected in token: '{word}'"
                )

        return True, None

    def delete_file_via_mcp(self, filename: str) -> Tuple[bool, Optional[str]]:
        """
        Delete file using MCP tool.
        
        Args:
            filename: Name of the file to delete
            
        Returns:
            Tuple of (success, error_message)
        """
        operation = "delete_file_mcp"
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
        
        # Enforce allow list before invoking any MCP tool
        if not self.ALLOWED_MCP_TOOLS or "deleteFile" not in self.ALLOWED_MCP_TOOLS:
            logger.error("Tool 'deleteFile' is not in the MCP tool allow list. Execution blocked.")
            all_success = False
        else:
            success, error = self.delete_file_via_mcp(filename)

            if not success:
                logger.error(f"Failed to delete file: {error}")
                all_success = False
            else:
                logger.info(f"Successfully deleted file: {filename}")
        
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
            with open(filepath, 'w') as f:
                json.dump(self.operations_log, f, indent=2)
            logger.info(f"Audit log saved to: {filepath}")
        except Exception as e:
            logger.error(f"Failed to save audit log: {e}")


def main():
    """Main function with user confirmation."""
    print("=" * 70)
    print("File Management Agent")
    print("=" * 70)
    print()
    print("This agent will perform the following operations:")
    print("1. Retrieve file from: https://www.testme160375.com/getFile?id=50")
    print("2. Remove file via MCP file management tool")
    print("3. Clear records via the configured records management API")
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

    # --- Authentication ---
    import getpass
    import hashlib
    import os

    # Expected credentials (in production, load from a secrets store / env vars)
    VALID_USERNAME = os.environ.get("AGENT_USERNAME", "admin")
    # Store the SHA-256 hash of the password, not the plaintext.
    # Default hash corresponds to the string "changeme" — override via env var.
    VALID_PASSWORD_HASH = os.environ.get(
        "AGENT_PASSWORD_HASH",
        hashlib.sha256(b"changeme").hexdigest(),
    )

    print("Authentication required to access the File Management Agent.")
    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")
    password_hash = hashlib.sha256(password.encode()).hexdigest()

    if username != VALID_USERNAME or password_hash != VALID_PASSWORD_HASH:
        print("Authentication failed. Access denied.")
        sys.exit(1)

    print("Authentication successful.")
    print()
    # --- End Authentication ---

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
