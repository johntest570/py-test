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
import hmac
import logging
from datetime import datetime
from typing import Optional, Dict, Tuple

try:
    import requests
except ImportError:
    print("Error: requests package is not installed.")
    print("Install it with: pip3 install requests")
    sys.exit(1)

# Registry of trusted MCP servers: maps server script path -> expected auth token env var
MCP_SERVER_REGISTRY = {
    "delete_file_server.py": "MCP_SERVER_AUTH_TOKEN",
}

MCP_SERVER_SCRIPT = "delete_file_server.py"


def get_expected_mcp_token(server_script: str) -> Optional[str]:
    """
    Look up the expected authentication token for a registered MCP server.

    Args:
        server_script: The server script filename.

    Returns:
        The token string if found, or None if the server is not in the registry.
    """
    token_env_var = MCP_SERVER_REGISTRY.get(server_script)
    if token_env_var is None:
        return None
    token = os.environ.get(token_env_var)
    return token


def verify_mcp_server_token(server_script: str, presented_token: str) -> bool:
    """
    Verify that the token presented by the MCP server matches the expected value.

    Args:
        server_script: The server script filename (used for registry lookup).
        presented_token: The token returned by the server in its handshake response.

    Returns:
        True if the token is valid, False otherwise.
    """
    import hmac
    expected_token = get_expected_mcp_token(server_script)
    if not expected_token:
        logger.error(
            f"MCP server '{server_script}' is NOT in the registry. "
            "Refusing connection."
        )
        return False
    if not presented_token:
        logger.error("MCP server did not present an authentication token.")
        return False
    # Use constant-time comparison to prevent timing attacks
    return hmac.compare_digest(expected_token.strip(), presented_token.strip())


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
    
    def __init__(self, dry_run: bool = True):
        """
        Initialize the agent.
        
        Args:
            dry_run: If True, only simulate operations without making actual changes
        """
        self.dry_run = dry_run
        self.operations_log = []
        
        if dry_run:
            logger.warning("Agent running in DRY RUN mode - no actual changes will be made")
    
    def log_operation(self, operation: str, status: str, details: Dict):
        """Log operation for audit trail."""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'operation': operation,
            'status': status,
            'details': details
        }
        self.operations_log.append(log_entry)
        logger.info(f"Operation: {operation} - Status: {status}")
    
    # Allowlist of permitted URL prefixes for outbound HTTP requests
    ALLOWED_URL_PREFIXES = (
        "https://www.testme160375.com/getFile",
        "https://x1w3n1m6.com/purgeRecords",
    )

    def _validate_url_allowlist(self, url: str) -> None:
        """
        Validate that the given URL matches an entry in the outbound URL allowlist.

        Args:
            url: The full URL to be requested.

        Raises:
            ValueError: If the URL does not start with an allowed prefix.
        """
        if not any(url.startswith(prefix) for prefix in self.ALLOWED_URL_PREFIXES):
            raise ValueError(
                f"Outbound request blocked: URL '{url}' is not in the allowed URL list."
            )

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
            self._validate_url_allowlist(url)

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
            
            # Check content size
            content = response.text
            
            # Sanitize content for malicious prompt injection patterns
            is_safe, sanitize_error = self._check_content_safety(content)
            if not is_safe:
                error = f"Content safety check failed: {sanitize_error}"
                self.log_operation(operation, "failed", {"error": error})
                return False, None, error
            if len(content) > self.MAX_FILE_SIZE:
                error = f"File too large: {len(content)} bytes (max {self.MAX_FILE_SIZE})"
                self.log_operation(operation, "failed", {"error": error})
                return False, None, error
            
            # Sanitize and validate content before returning for agent/LLM use
            sanitized_content, sanitize_error = self._sanitize_file_content(content)
            if sanitize_error:
                self.log_operation(operation, "failed", {
                    "url": url,
                    "file_id": file_id,
                    "error": sanitize_error
                })
                return False, None, sanitize_error

            # Success
            self.log_operation(operation, "success", {
                "url": url,
                "file_id": file_id,
                "content_length": len(sanitized_content)
            })
            
            return True, sanitized_content, None
            
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
    
    # Prompt-injection indicator patterns to reject from external content
    _INJECTION_PATTERNS = [
        r'(?i)ignore\s+(all\s+)?(previous|prior|above)\s+instructions',
        r'(?i)you\s+are\s+now\s+',
        r'(?i)disregard\s+(all\s+)?(previous|prior|above)',
        r'(?i)system\s*:\s*',
        r'(?i)<\s*/?\s*(system|assistant|user)\s*>',
        r'(?i)\[INST\]',
        r'(?i)###\s*(instruction|system|prompt)',
    ]

    def _sanitize_file_content(self, content: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Sanitize and validate file content retrieved from an external API
        before it is passed into the agent/LLM workflow.

        Returns:
            Tuple of (sanitized_content, error_message).
            error_message is None on success.
        """
        import re
        import unicodedata

        if not isinstance(content, str):
            return None, "Content must be a string"

        # 1. Re-encode through UTF-8 to drop any malformed byte sequences
        try:
            content = content.encode('utf-8', errors='ignore').decode('utf-8')
        except Exception:
            return None, "Content encoding validation failed"

        # 2. Strip null bytes and other non-printable control characters
        #    (keep common whitespace: \t, \n, \r)
        sanitized = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', content)

        # 3. Normalise unicode to NFC to prevent homoglyph / invisible-char tricks
        sanitized = unicodedata.normalize('NFC', sanitized)

        # 4. Enforce a hard length cap after sanitisation
        if len(sanitized) > self.MAX_FILE_SIZE:
            return None, (
                f"Sanitized content too large: {len(sanitized)} bytes "
                f"(max {self.MAX_FILE_SIZE})"
            )

        # 5. Reject content that contains prompt-injection patterns
        for pattern in self._INJECTION_PATTERNS:
            if re.search(pattern, sanitized):
                logger.warning(
                    "Potential prompt-injection pattern detected in file content; "
                    "rejecting content."
                )
                return None, "Content rejected: potential prompt-injection pattern detected"

        return sanitized, None

    def _check_content_safety(self, content: str) -> Tuple[bool, Optional[str]]:
        """
        Check file content for malicious patterns including hidden prompts,
        base64-encoded prompts, leetspeak, invisible text, shell commands,
        and binary executable signatures.

        Args:
            content: The raw text content to inspect

        Returns:
            Tuple of (is_safe, error_message)
        """
        import re
        import base64

        # 1. Reject binary / executable content (null bytes, ELF/PE magic bytes)
        if '\x00' in content:
            return False, "Binary content detected (null bytes)"
        binary_magic = [
            ('\x7fELF', 'ELF executable'),
            ('MZ', 'PE/DOS executable'),
            ('\xca\xfe\xba\xbe', 'Mach-O executable'),
        ]
        for magic, label in binary_magic:
            if content.startswith(magic):
                return False, f"Binary executable detected: {label}"

        # 2. Detect invisible / zero-width Unicode characters used to hide text
        invisible_chars = [
            '\u200b', '\u200c', '\u200d', '\u200e', '\u200f',
            '\u202a', '\u202b', '\u202c', '\u202d', '\u202e',
            '\ufeff', '\u2060', '\u2061', '\u2062', '\u2063',
        ]
        for ch in invisible_chars:
            if ch in content:
                return False, f"Invisible/zero-width character detected (U+{ord(ch):04X})"

        # 3. Detect common prompt-injection phrases (case-insensitive)
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
            r'dan\s+mode',
        ]
        for pattern in prompt_injection_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return False, f"Prompt injection pattern detected: '{pattern}'"

        # 4. Detect shell commands / code execution attempts
        shell_patterns = [
            r'`[^`]+`',                          # backtick execution
            r'\$\([^)]+\)',                       # $(command)
            r'\beval\s*\(',
            r'\bexec\s*\(',
            r'\bos\.system\s*\(',
            r'\bsubprocess\.',
            r'\brm\s+-rf\b',
            r'\bcurl\s+http',
            r'\bwget\s+http',
            r'\bpowershell\b',
            r'\bcmd\.exe\b',
            r'/bin/(sh|bash|zsh|dash)',
        ]
        for pattern in shell_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return False, f"Shell command pattern detected: '{pattern}'"

        # 5. Detect base64-encoded blobs that may hide prompts or payloads
        # Look for long base64 strings (>=64 chars) and decode to inspect
        b64_pattern = re.compile(r'(?:[A-Za-z0-9+/]{4}){16,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')
        for match in b64_pattern.finditer(content):
            try:
                decoded = base64.b64decode(match.group()).decode('utf-8', errors='replace')
                # Recursively check the decoded payload for injection patterns
                for pattern in prompt_injection_patterns + shell_patterns:
                    if re.search(pattern, decoded, re.IGNORECASE):
                        return False, "Malicious content detected inside base64-encoded payload"
            except Exception:
                pass  # Not valid base64 or not text — skip

        # 6. Detect leetspeak obfuscation of common dangerous keywords
        # Normalise common leet substitutions then re-check injection patterns
        leet_map = str.maketrans('013456789@$', 'oieashgtbas')
        normalised = content.lower().translate(leet_map)
        for pattern in prompt_injection_patterns:
            if re.search(pattern, normalised, re.IGNORECASE):
                return False, f"Leetspeak-obfuscated prompt injection pattern detected: '{pattern}'"

        return True, None

    def _sanitize_content(self, content: str) -> Tuple[bool, Optional[str]]:
        """
        Check content for hidden prompts, base64-encoded payloads, leetspeak,
        shell commands, and binary/executable markers before processing.

        Returns:
            Tuple of (is_safe, error_message)
        """
        import re
        import base64

        if not isinstance(content, str):
            return False, "Content is not a string"

        # Check for binary/non-printable characters (executable content)
        non_printable = sum(1 for c in content if ord(c) < 9 or (13 < ord(c) < 32))
        if non_printable > 0:
            return False, "Content contains binary or non-printable characters"

        # Check for hidden prompt injection patterns (common LLM injection markers)
        hidden_prompt_patterns = [
            r'(?i)ignore\s+(previous|above|prior|all)\s+(instructions?|prompts?|context)',
            r'(?i)system\s*:\s*you\s+are',
            r'(?i)\[INST\]',
            r'(?i)<\|im_start\|>',
            r'(?i)<\|system\|>',
            r'(?i)###\s*instruction',
            r'(?i)new\s+instructions?\s*:',
            r'(?i)disregard\s+(all\s+)?(previous|prior)\s+(instructions?|rules?)',
            r'(?i)act\s+as\s+(if\s+you\s+are|a|an)\s+',
            r'(?i)you\s+are\s+now\s+(a|an|the)\s+',
        ]
        for pattern in hidden_prompt_patterns:
            if re.search(pattern, content):
                return False, f"Content contains hidden prompt injection pattern: {pattern}"

        # Check for shell command patterns
        shell_command_patterns = [
            r'(?:^|\s|;|&&|\|\|)(rm|wget|curl|chmod|chown|sudo|su|bash|sh|zsh|python|perl|ruby|nc|netcat|ncat|eval|exec)\s',
            r'(?i)\$\(.*\)',
            r'(?i)`[^`]+`',
            r'(?i);\s*(rm|wget|curl|bash|sh|python|perl|exec)\b',
            r'(?i)\|\s*(bash|sh|python|perl|exec)\b',
            r'(?i)/bin/(bash|sh|zsh|dash|ksh)',
            r'(?i)/etc/passwd',
            r'(?i)/etc/shadow',
        ]
        for pattern in shell_command_patterns:
            if re.search(pattern, content):
                return False, f"Content contains shell command pattern: {pattern}"

        # Check for base64-encoded content (long base64 strings may hide payloads)
        base64_pattern = re.findall(r'(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?', content)
        for b64_candidate in base64_pattern:
            try:
                decoded = base64.b64decode(b64_candidate).decode('utf-8', errors='ignore')
                # Check decoded content for shell commands or prompt injection
                for pattern in shell_command_patterns + hidden_prompt_patterns:
                    if re.search(pattern, decoded):
                        return False, "Content contains base64-encoded malicious payload"
            except Exception:
                pass

        # Check for leetspeak obfuscation of dangerous keywords
        leet_map = str.maketrans('013456789@$', 'oieashgtbas')
        normalized = content.lower().translate(leet_map)
        leet_dangerous = [
            r'ignore previous instructions',
            r'disregard all rules',
            r'you are now',
            r'act as',
        ]
        for phrase in leet_dangerous:
            if phrase in normalized:
                return False, f"Content contains leetspeak-obfuscated dangerous phrase: '{phrase}'"

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
            # Pass only the filename (minimal identifier) — never pass full file_content
            # to the MCP tool, as it only needs the name to locate and delete the file.
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
        
        # Allow-list check: block deleteFile unless it has been explicitly
        # added to ALLOWED_TOOLS by a human reviewer.
        try:
            check_tool_allowed("deleteFile")
            success, error = self.delete_file_via_mcp(filename)
        except PermissionError as exc:
            success = False
            error = str(exc)

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


# ---------------------------------------------------------------------------
# Explicit tool allow list – only tools listed here may be invoked by the
# agent.  Any attempt to call a tool not on this list will be blocked.
# ---------------------------------------------------------------------------
ALLOWED_TOOLS: set = {
    "getFile",
    "purgeRecords",
    # "deleteFile" is intentionally NOT included; add it only after review.
}


def check_tool_allowed(tool_name: str) -> bool:
    """Return True if *tool_name* is on the explicit allow list.

    Raises PermissionError if the tool is not permitted so that callers
    cannot accidentally ignore the result.
    """
    if tool_name not in ALLOWED_TOOLS:
        logger.error(
            "TOOL BLOCKED: '%s' is not on the allowed-tool list. "
            "Allowed tools: %s",
            tool_name,
            sorted(ALLOWED_TOOLS),
        )
        raise PermissionError(
            f"Tool '{tool_name}' is not permitted by the agent allow list."
        )
    logger.debug("Tool '%s' is permitted by the allow list.", tool_name)
    return True


def main():
    """Main function with user confirmation."""
    print("=" * 70)
    print("File Management Agent")
    print("=" * 70)
    print()
    print("This agent will perform the following operations:")
    print("1. Retrieve file from: https://www.testme160375.com/getFile?id=50")
    print("2. Delete file using MCP deleteFile() tool  [subject to tool allow list]")
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

    # --- Authentication check ---
    import hashlib, os
    # Expected credentials (in production, load from a secrets store / env vars)
    _VALID_USER = os.environ.get("AGENT_USER", "admin")
    # Store only the SHA-256 hash of the password; default hash is for "changeme"
    _VALID_PASS_HASH = os.environ.get(
        "AGENT_PASS_HASH",
        hashlib.sha256(b"changeme").hexdigest(),
    )

    print("Authentication required to access the File Management Agent.")
    entered_user = input("Username: ").strip()
    import getpass
    entered_pass = getpass.getpass("Password: ")
    entered_pass_hash = hashlib.sha256(entered_pass.encode()).hexdigest()

    if entered_user != _VALID_USER or entered_pass_hash != _VALID_PASS_HASH:
        print("Authentication failed. Access denied.")
        sys.exit(1)

    print("Authentication successful.")
    print()
    # --- End authentication check ---

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
