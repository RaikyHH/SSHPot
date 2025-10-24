# security_hardening.py

"""
Security Hardening Module for SSHPot Honeypot

Provides security utilities to protect against common attack vectors:
- File upload size limits and streaming
- Path traversal prevention
- Filename sanitization
- Authentication rate limiting
- Input validation
"""

import os
import re
import time
import tempfile
import hashlib
from pathlib import Path
from collections import defaultdict, OrderedDict
from typing import Optional, Tuple, Dict, Any


# ============================================================================
# Configuration Constants
# ============================================================================

# File Upload Limits
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB per file
MAX_TOTAL_QUARANTINE_SIZE = 10 * 1024 * 1024 * 1024  # 10GB total
MAX_FILENAME_LENGTH = 255

# SCP Protocol Limits
MAX_SCP_ITERATIONS = 1000  # Maximum SCP commands per session
MAX_SCP_DURATION = 300  # 5 minutes maximum per SCP session
SCP_TIMEOUT = 30  # 30 seconds per operation

# Rate Limiting
MAX_AUTH_ATTEMPTS = 5  # Per IP
AUTH_WINDOW_SECONDS = 60  # 1 minute window

# Session Management
MAX_CACHED_SESSIONS = 1000  # LRU cache for session contexts


# ============================================================================
# Path Security
# ============================================================================

class SecurePath:
    """
    Secure path handling to prevent directory traversal attacks.
    """

    # Forbidden path prefixes (simulated system paths that shouldn't be accessible)
    FORBIDDEN_PREFIXES = ['/proc/', '/sys/', '/dev/', '/run/', '/boot/']

    @staticmethod
    def normalize_path(path: str, cwd: str = '/root') -> str:
        """
        Normalize path and prevent traversal outside virtual root.

        Args:
            path: Path to normalize (relative or absolute)
            cwd: Current working directory

        Returns:
            Normalized absolute path within virtual filesystem
        """
        # Always use forward slashes (Unix-style paths for virtual filesystem)
        path = path.replace('\\', '/')
        cwd = cwd.replace('\\', '/')

        # Resolve relative to cwd
        if path.startswith('/'):
            resolved = path
        else:
            # Manually join paths using forward slashes
            if cwd.endswith('/'):
                resolved = cwd + path
            else:
                resolved = cwd + '/' + path

        # Split path into components
        parts = resolved.split('/')
        normalized_parts = []

        for part in parts:
            if part == '..':
                # Go up one level (but not above root)
                if normalized_parts and normalized_parts[-1] != '':
                    normalized_parts.pop()
            elif part and part != '.':
                normalized_parts.append(part)

        # Reconstruct path
        if not normalized_parts:
            normalized = '/'
        else:
            normalized = '/' + '/'.join(normalized_parts)

        # Check for forbidden paths
        for prefix in SecurePath.FORBIDDEN_PREFIXES:
            if normalized.startswith(prefix):
                # Redirect to safe fake path
                normalized = '/root/simulated' + normalized

        return normalized

    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """
        Sanitize filename to prevent injection attacks.

        Args:
            filename: Original filename from attacker

        Returns:
            Sanitized safe filename
        """
        # Limit length
        if len(filename) > MAX_FILENAME_LENGTH:
            filename = filename[:MAX_FILENAME_LENGTH]

        # Remove path components (only allow base filename)
        filename = os.path.basename(filename)

        # Remove control characters and dangerous characters
        filename = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', filename)
        filename = re.sub(r'[<>:"|?*\\]', '_', filename)

        # Ensure filename is not empty after sanitization
        if not filename or filename in ('.', '..', ''):
            filename = f'unnamed_file_{int(time.time())}'

        # Additional: limit to safe character set (optional strictness)
        # Uncomment to enforce alphanumeric + basic punctuation only
        # if not re.match(r'^[a-zA-Z0-9._-]+$', filename):
        #     filename = f"suspicious_file_{int(time.time())}"

        return filename


# ============================================================================
# File Upload Security (SCP)
# ============================================================================

class SecureFileUploadHandler:
    """
    Handles file uploads with size limits, streaming to disk, and validation.
    """

    def __init__(self, quarantine_dir: str = "quarantine"):
        """
        Initialize secure file upload handler.

        Args:
            quarantine_dir: Base quarantine directory
        """
        self.quarantine_dir = Path(quarantine_dir)
        self.files_dir = self.quarantine_dir / "files"
        self.metadata_dir = self.quarantine_dir / "metadata"

        # Ensure directories exist
        self.files_dir.mkdir(parents=True, exist_ok=True)
        self.metadata_dir.mkdir(parents=True, exist_ok=True)

    def get_total_quarantine_size(self) -> int:
        """
        Calculate total size of quarantined files.

        Returns:
            Total size in bytes
        """
        total_size = 0
        try:
            for file_path in self.files_dir.iterdir():
                if file_path.is_file():
                    total_size += file_path.stat().st_size
        except Exception as e:
            print(f"[Security] Error calculating quarantine size: {e}")

        return total_size

    def validate_upload(self, file_size: int) -> Tuple[bool, Optional[str]]:
        """
        Validate if file upload should be accepted.

        Args:
            file_size: Size of file to upload

        Returns:
            Tuple of (is_valid, error_message)
        """
        # Check individual file size limit
        if file_size > MAX_FILE_SIZE:
            return False, f"File too large ({file_size} bytes, max {MAX_FILE_SIZE})"

        # Check total quarantine size limit
        current_size = self.get_total_quarantine_size()
        if current_size + file_size > MAX_TOTAL_QUARANTINE_SIZE:
            return False, f"Quarantine quota exceeded ({current_size} + {file_size} > {MAX_TOTAL_QUARANTINE_SIZE})"

        return True, None

    def stream_upload_to_disk(self, channel, file_size: int) -> Tuple[Optional[str], Optional[bytes]]:
        """
        Stream file upload directly to disk (prevents memory exhaustion).

        Args:
            channel: Paramiko channel to read from
            file_size: Expected file size

        Returns:
            Tuple of (temp_file_path, sha256_hash) or (None, None) on error
        """
        temp_file = None
        sha256_hasher = hashlib.sha256()

        try:
            # Create temporary file
            temp_file = tempfile.NamedTemporaryFile(delete=False, dir=self.quarantine_dir)

            remaining = file_size
            while remaining > 0:
                chunk_size = min(remaining, 8192)
                chunk = channel.recv(chunk_size)

                if not chunk:
                    raise ValueError("Connection closed during upload")

                # Write to disk and update hash simultaneously
                temp_file.write(chunk)
                sha256_hasher.update(chunk)
                remaining -= len(chunk)

            temp_file.close()

            # Verify file size matches
            actual_size = os.path.getsize(temp_file.name)
            if actual_size != file_size:
                os.unlink(temp_file.name)
                raise ValueError(f"Size mismatch: expected {file_size}, got {actual_size}")

            return temp_file.name, sha256_hasher.digest()

        except Exception as e:
            print(f"[Security] Upload streaming error: {e}")
            if temp_file:
                try:
                    temp_file.close()
                    os.unlink(temp_file.name)
                except:
                    pass
            return None, None


# ============================================================================
# Rate Limiting
# ============================================================================

class AuthRateLimiter:
    """
    Rate limiter for authentication attempts to prevent brute-force attacks.
    """

    def __init__(self, max_attempts: int = MAX_AUTH_ATTEMPTS, window_seconds: int = AUTH_WINDOW_SECONDS):
        """
        Initialize rate limiter.

        Args:
            max_attempts: Maximum attempts allowed per window
            window_seconds: Time window in seconds
        """
        self.attempts = defaultdict(list)
        self.max_attempts = max_attempts
        self.window = window_seconds

    def is_allowed(self, ip_address: str) -> bool:
        """
        Check if authentication attempt from IP is allowed.

        Args:
            ip_address: IP address to check

        Returns:
            True if attempt is allowed, False if rate limited
        """
        now = time.time()

        # Clean old attempts outside the window
        self.attempts[ip_address] = [
            t for t in self.attempts[ip_address]
            if now - t < self.window
        ]

        # Check if limit exceeded
        if len(self.attempts[ip_address]) >= self.max_attempts:
            return False

        # Record this attempt
        self.attempts[ip_address].append(now)
        return True

    def cleanup_old_entries(self):
        """
        Remove old entries to prevent memory leak.
        Should be called periodically.
        """
        now = time.time()
        ips_to_remove = []

        for ip, timestamps in self.attempts.items():
            # Remove timestamps outside window
            timestamps[:] = [t for t in timestamps if now - t < self.window]

            # Mark IP for removal if no recent attempts
            if not timestamps:
                ips_to_remove.append(ip)

        for ip in ips_to_remove:
            del self.attempts[ip]


# ============================================================================
# Session Management with LRU Cache
# ============================================================================

class SessionContextManager:
    """
    Manages session contexts with LRU eviction to prevent memory leaks.
    """

    def __init__(self, max_cached: int = MAX_CACHED_SESSIONS):
        """
        Initialize session context manager.

        Args:
            max_cached: Maximum number of cached sessions
        """
        self.contexts = OrderedDict()
        self.max_cached = max_cached

    def get_context(self, session_id: str) -> Dict[str, Any]:
        """
        Get or create session context.

        Args:
            session_id: Session identifier

        Returns:
            Session context dictionary
        """
        if session_id not in self.contexts:
            # Evict oldest entry if cache is full
            if len(self.contexts) >= self.max_cached:
                self.contexts.popitem(last=False)

            # Create new context
            self.contexts[session_id] = {
                'cwd': '/root',
                'user': 'root',
                'hostname': 'debian',
                'home': '/root',
                'env': {}
            }
        else:
            # Move to end (mark as recently used)
            self.contexts.move_to_end(session_id)

        return self.contexts[session_id]

    def cleanup_session(self, session_id: str):
        """
        Remove session context when session ends.

        Args:
            session_id: Session to clean up
        """
        self.contexts.pop(session_id, None)


# ============================================================================
# Input Validation
# ============================================================================

class InputValidator:
    """
    Validates various inputs to prevent injection and malformed data attacks.
    """

    @staticmethod
    def validate_file_mode(mode_str: str) -> Optional[int]:
        """
        Validate Unix file mode (octal permissions).

        Args:
            mode_str: Octal mode string (e.g., "0644")

        Returns:
            Integer mode or None if invalid
        """
        try:
            file_mode = int(mode_str, 8)

            # Validate Unix permissions range (0000-7777 octal)
            if file_mode < 0 or file_mode > 0o7777:
                return None

            return file_mode

        except ValueError:
            return None

    @staticmethod
    def sanitize_log_string(text: str, max_length: int = 10000) -> str:
        """
        Sanitize string for safe logging (prevent log injection).

        Args:
            text: Text to sanitize
            max_length: Maximum allowed length

        Returns:
            Sanitized string
        """
        # Limit length
        if len(text) > max_length:
            text = text[:max_length] + "...[truncated]"

        # Remove control characters except tab and space
        text = re.sub(r'[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f-\x9f]', '', text)

        # Replace newlines to prevent log injection
        text = text.replace('\n', '\\n').replace('\r', '\\r')

        return text
