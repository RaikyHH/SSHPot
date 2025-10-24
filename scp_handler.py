# scp_handler.py

"""
SCP Protocol Handler for SSH Honeypot

Implements SCP file reception for forensic analysis. Files uploaded by attackers
are stored securely with comprehensive metadata in an isolated quarantine directory.
Files are never executed.
"""

import os
import hashlib
import json
import time
from pathlib import Path
from typing import Optional, Dict, Tuple
from datetime import datetime


class SCPReceiver:
    """
    Handles SCP file uploads from attackers.
    Stores files securely with forensic metadata.
    """

    def __init__(self, base_quarantine_dir: str = "quarantine"):
        """
        Initialize SCP receiver.

        Args:
            base_quarantine_dir: Base directory for storing uploaded files
        """
        self.base_quarantine_dir = Path(base_quarantine_dir)
        self._ensure_quarantine_structure()

    def _ensure_quarantine_structure(self):
        """Create quarantine directory structure if it doesn't exist."""
        self.base_quarantine_dir.mkdir(exist_ok=True)

        # Create subdirectories for organization
        (self.base_quarantine_dir / "files").mkdir(exist_ok=True)
        (self.base_quarantine_dir / "metadata").mkdir(exist_ok=True)

    def receive_file(
        self,
        session_id: str,
        client_ip: str,
        filename: str,
        file_data: bytes,
        file_mode: int = 0o644,
        timestamp: Optional[float] = None
    ) -> Dict:
        """
        Receive and store a file uploaded via SCP.

        Args:
            session_id: Session ID of the attacker
            client_ip: IP address of the attacker
            filename: Original filename from the attacker
            file_data: Raw file content
            file_mode: File permissions (Unix mode)
            timestamp: Optional timestamp (defaults to current time)

        Returns:
            Dictionary containing forensic metadata about the stored file
        """
        timestamp = timestamp or time.time()

        # Calculate file hashes
        sha256_hash = hashlib.sha256(file_data).hexdigest()
        md5_hash = hashlib.md5(file_data).hexdigest()

        # Create forensic metadata
        metadata = {
            "session_id": session_id,
            "client_ip": client_ip,
            "original_filename": filename,
            "upload_timestamp": timestamp,
            "upload_datetime": datetime.fromtimestamp(timestamp).isoformat(),
            "file_size_bytes": len(file_data),
            "sha256": sha256_hash,
            "md5": md5_hash,
            "file_mode_octal": oct(file_mode),
            "quarantine_filename": f"{sha256_hash}.bin",
            "metadata_filename": f"{sha256_hash}.json"
        }

        # Store the file using SHA256 as filename (prevents duplicates and name collisions)
        file_path = self.base_quarantine_dir / "files" / metadata["quarantine_filename"]

        # Only write if file doesn't already exist (deduplication)
        if not file_path.exists():
            with open(file_path, 'wb') as f:
                f.write(file_data)
            metadata["stored_new_file"] = True
        else:
            metadata["stored_new_file"] = False
            metadata["note"] = "File with same SHA256 already exists (deduplicated)"

        # Always store metadata (even for duplicates, to track multiple uploads)
        metadata_path = self.base_quarantine_dir / "metadata" / f"{session_id}_{int(timestamp)}_{sha256_hash[:16]}.json"
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)

        return metadata

    def parse_scp_command(self, command: str) -> Optional[Tuple[str, str, bool]]:
        """
        Parse SCP command to determine operation type.

        Args:
            command: Full SCP command string

        Returns:
            Tuple of (mode, target_path, is_recursive) or None if not SCP
            mode can be 'sink' (receive) or 'source' (send)
        """
        if not command.startswith('scp '):
            return None

        parts = command.split()

        # SCP sink mode (receive files): scp -t [path]
        # SCP source mode (send files): scp -f [path]
        mode = None
        is_recursive = False
        target_path = None

        i = 1
        while i < len(parts):
            part = parts[i]

            if part == '-t':
                mode = 'sink'
            elif part == '-f':
                mode = 'source'
            elif part == '-r':
                is_recursive = True
            elif not part.startswith('-'):
                target_path = part
                break

            i += 1

        return (mode, target_path or "/tmp", is_recursive)


class SCPProtocolHandler:
    """
    Implements the SCP protocol for receiving files.

    SCP Protocol Overview:
    1. Client sends: scp -t /remote/path
    2. Server responds: 0x00 (OK)
    3. Client sends: C0644 <size> <filename>\n
    4. Server responds: 0x00 (OK)
    5. Client sends: <file_data>
    6. Server responds: 0x00 (OK)
    7. Client sends: 0x00 (done)
    """

    # Protocol bytes
    OK = b'\x00'
    ERROR = b'\x01'
    FATAL_ERROR = b'\x02'

    def __init__(self, receiver: SCPReceiver, session_id: str, client_ip: str):
        """
        Initialize SCP protocol handler.

        Args:
            receiver: SCPReceiver instance for storing files
            session_id: Session ID
            client_ip: Client IP address
        """
        self.receiver = receiver
        self.session_id = session_id
        self.client_ip = client_ip
        self.files_received = []

    async def handle_sink_mode(self, channel, target_path: str) -> list:
        """
        Handle SCP sink mode (receiving files from attacker).

        Args:
            channel: Paramiko channel
            target_path: Target path from SCP command

        Returns:
            List of metadata dictionaries for received files
        """
        import socket

        print(f"[SCP] Entering sink mode for {self.client_ip}, target: {target_path}")

        try:
            # Send initial OK to start the transfer
            try:
                channel.send(self.OK)
            except (OSError, EOFError) as e:
                print(f"[SCP] Failed to send initial OK: {e}")
                return self.files_received

            while True:
                # Read command byte or line
                try:
                    command = self._read_line(channel)
                except (OSError, EOFError, socket.timeout) as e:
                    print(f"[SCP] Connection error reading command: {e}")
                    break

                if not command:
                    print(f"[SCP] Empty command, ending transfer")
                    break

                # Check for end of transfer
                if command == b'\x00':
                    print(f"[SCP] End of transfer signal received")
                    break

                # Parse file/directory command
                if command[0:1] == b'C':
                    # File transfer: C<mode> <size> <filename>
                    try:
                        metadata = await self._receive_file(channel, command)
                        if metadata:
                            self.files_received.append(metadata)
                    except (OSError, EOFError, socket.timeout) as e:
                        print(f"[SCP] Connection error during file transfer: {e}")
                        break

                elif command[0:1] == b'D':
                    # Directory: D<mode> 0 <dirname>
                    # For honeypot, we just acknowledge but don't create directories
                    try:
                        channel.send(self.OK)
                    except (OSError, EOFError) as e:
                        print(f"[SCP] Connection error sending directory ACK: {e}")
                        break

                elif command[0:1] == b'E':
                    # End directory
                    try:
                        channel.send(self.OK)
                    except (OSError, EOFError) as e:
                        print(f"[SCP] Connection error sending end directory ACK: {e}")
                        break

                elif command[0:1] == b'T':
                    # Timestamp: T<mtime> 0 <atime> 0
                    # Acknowledge but ignore for now
                    try:
                        channel.send(self.OK)
                    except (OSError, EOFError) as e:
                        print(f"[SCP] Connection error sending timestamp ACK: {e}")
                        break

                else:
                    print(f"[SCP] Unknown command: {command[:20]}")
                    break

            print(f"[SCP] Transfer complete. Received {len(self.files_received)} file(s)")
            return self.files_received

        except (OSError, EOFError, socket.timeout) as e:
            print(f"[SCP] Connection error during transfer: {e}")
            return self.files_received
        except Exception as e:
            print(f"[SCP] Unexpected error during transfer: {e}")
            import traceback
            traceback.print_exc()
            try:
                channel.send(self.FATAL_ERROR)
            except:
                pass
            return self.files_received

    async def _receive_file(self, channel, command: bytes) -> Optional[Dict]:
        """
        Receive a single file.

        Args:
            channel: Paramiko channel
            command: C command line (C<mode> <size> <filename>)

        Returns:
            Metadata dictionary or None if failed
        """
        import socket

        try:
            # Parse: C0644 1234 filename.txt
            parts = command.decode('utf-8', errors='ignore').strip().split(' ', 2)
            if len(parts) < 3:
                channel.send(self.ERROR + b'Invalid C command\n')
                return None

            mode_str = parts[0][1:]  # Remove 'C' prefix
            file_size = int(parts[1])
            filename = parts[2]

            print(f"[SCP] Receiving file: {filename} ({file_size} bytes, mode {mode_str})")

            # Validate file size (prevent DoS)
            max_file_size = 100 * 1024 * 1024  # 100 MB limit
            if file_size > max_file_size:
                print(f"[SCP] File too large: {file_size} bytes (max {max_file_size})")
                channel.send(self.ERROR + b'File too large\n')
                return None

            # Send OK to proceed
            channel.send(self.OK)

            # Set timeout for file transfer
            original_timeout = channel.gettimeout()
            channel.settimeout(60.0)  # 60 second timeout for file transfer

            # Receive file data
            file_data = b''
            remaining = file_size

            try:
                while remaining > 0:
                    chunk_size = min(remaining, 8192)
                    chunk = channel.recv(chunk_size)
                    if not chunk:
                        print(f"[SCP] Connection closed while receiving file data")
                        break
                    file_data += chunk
                    remaining -= len(chunk)

                # Read trailing null byte
                try:
                    channel.recv(1)
                except (socket.timeout, OSError, EOFError):
                    pass  # Trailing byte is optional

            except socket.timeout:
                print(f"[SCP] Timeout while receiving file data")
                channel.send(self.ERROR + b'Transfer timeout\n')
                return None
            except (OSError, EOFError) as e:
                print(f"[SCP] Connection error while receiving file: {e}")
                return None
            finally:
                # Restore original timeout
                channel.settimeout(original_timeout)

            # Verify we received complete file
            if len(file_data) != file_size:
                print(f"[SCP] Incomplete file: received {len(file_data)} bytes, expected {file_size}")
                channel.send(self.ERROR + b'Incomplete transfer\n')
                return None

            # Store the file
            file_mode = int(mode_str, 8)  # Convert octal string to int
            metadata = self.receiver.receive_file(
                session_id=self.session_id,
                client_ip=self.client_ip,
                filename=filename,
                file_data=file_data,
                file_mode=file_mode
            )

            print(f"[SCP] File stored: {metadata['sha256']}")

            # Send final OK
            channel.send(self.OK)

            return metadata

        except Exception as e:
            print(f"[SCP] Error receiving file: {e}")
            import traceback
            traceback.print_exc()
            try:
                channel.send(self.ERROR + f"{e}\n".encode())
            except:
                pass
            return None

    def _read_line(self, channel, max_len: int = 8192, timeout: float = 30.0) -> bytes:
        """
        Read a line from the channel (up to newline or max_len).

        Args:
            channel: Paramiko channel
            max_len: Maximum bytes to read
            timeout: Timeout in seconds for read operations

        Returns:
            Line data (without newline)
        """
        import socket

        # Set channel timeout
        original_timeout = channel.gettimeout()
        channel.settimeout(timeout)

        line = b''
        try:
            while len(line) < max_len:
                try:
                    char = channel.recv(1)
                    if not char:
                        break
                    if char == b'\n':
                        break
                    line += char
                except socket.timeout:
                    print(f"[SCP] Timeout reading from channel after {timeout}s")
                    break
                except (OSError, EOFError) as e:
                    print(f"[SCP] Connection error while reading: {e}")
                    break
        finally:
            # Restore original timeout
            channel.settimeout(original_timeout)

        return line
