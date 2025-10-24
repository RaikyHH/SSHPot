# ssh_server_paramiko.py

import paramiko
import socket
import threading
import sys
from pathlib import Path
from command_processor import CommandProcessor


class SSHServerInterface(paramiko.ServerInterface):
    """
    SSH Server Interface for Paramiko.
    Handles authentication and channel requests.
    """

    def __init__(self, config_engine, state_manager, logger, session_id, client_ip):
        """Initialize SSH server interface."""
        self.config_engine = config_engine
        self.state_manager = state_manager
        self.logger = logger
        self.session_id = session_id
        self.client_ip = client_ip
        self.protocol_config = config_engine.get_protocol_config('ssh')
        self.authenticated_user = None
        self.event = threading.Event()
        self.exec_command = None  # Store exec command for SCP/other non-shell requests

    def check_channel_request(self, kind, chanid):
        """Handle channel open requests."""
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        """
        Handle password authentication.

        Args:
            username: Username provided by client
            password: Password provided by client

        Returns:
            AUTH_SUCCESSFUL or AUTH_FAILED
        """
        print(f"[SSH-Paramiko] Auth attempt from {self.client_ip}: user='{username}', pass='{password}'")

        # Log authentication attempt
        self.logger._log("SSH_AUTH_ATTEMPT", self.session_id, {
            "username": username,
            "password": password,
            "method": "password"
        })

        # Check credentials
        valid_users = self.protocol_config.get('users', {})

        if username in valid_users and valid_users[username] == password:
            print(f"[SSH-Paramiko] Authentication SUCCESS for {username} from {self.client_ip}")
            self.authenticated_user = username

            self.logger._log("SSH_AUTH_SUCCESS", self.session_id, {
                "username": username,
                "password": password
            })

            return paramiko.AUTH_SUCCESSFUL
        else:
            print(f"[SSH-Paramiko] Authentication FAILED for {username} from {self.client_ip}")

            self.logger._log("SSH_AUTH_FAILURE", self.session_id, {
                "username": username,
                "password": password
            })

            return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        """Reject public key authentication (password-only honeypot)."""
        print(f"[SSH-Paramiko] Public key auth attempted by {username} from {self.client_ip} - REJECTED")

        self.logger._log("SSH_AUTH_ATTEMPT", self.session_id, {
            "username": username,
            "method": "publickey",
            "key_type": key.get_name(),
            "status": "rejected"
        })

        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        """Return allowed authentication methods."""
        return 'password'

    def check_channel_shell_request(self, channel):
        """Handle shell request."""
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        """Handle PTY request."""
        return True

    def check_channel_exec_request(self, channel, command):
        """Handle exec request (used by SCP and other commands)."""
        # Decode command if it's bytes
        if isinstance(command, bytes):
            command = command.decode('utf-8', errors='ignore')

        print(f"[SSH-Paramiko] Exec request: {command}")
        self.exec_command = command
        self.event.set()
        return True


class SSHHoneypotServer:
    """
    Full SSH Honeypot Server using Paramiko.
    Provides complete SSH-2.0 protocol support for PuTTY/OpenSSH compatibility.
    """

    def __init__(self, config_engine, state_manager, logger, dynamic_processor=None, host_key_file='ssh_host_rsa_key'):
        """Initialize the SSH honeypot server."""
        self.config_engine = config_engine
        self.state_manager = state_manager
        self.logger = logger
        self.dynamic_processor = dynamic_processor
        self.host_key_file = host_key_file
        self.host_key = None
        self.protocol_config = config_engine.get_protocol_config('ssh')
        self.running = False
        self.server_socket = None

        # Rate limiting: Track connections per IP
        self.connection_counts = {}  # {ip: [timestamp1, timestamp2, ...]}
        self.MAX_CONNECTIONS_PER_IP = 10  # Max connections per IP in time window
        self.RATE_LIMIT_WINDOW = 60  # Time window in seconds

    def load_host_key(self):
        """Load SSH host key."""
        try:
            self.host_key = paramiko.RSAKey(filename=self.host_key_file)
            print(f"[SSH-Paramiko] Loaded host key from {self.host_key_file}")
            return True
        except Exception as e:
            print(f"[SSH-Paramiko] ERROR: Failed to load host key: {e}")
            print(f"[SSH-Paramiko] Run: python generate_host_key.py")
            return False

    async def start_server(self):
        """Start the SSH server (async wrapper for compatibility)."""
        import asyncio
        # Run in thread pool to not block async event loop
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._start_server_sync)

    def _start_server_sync(self):
        """Start the SSH server (synchronous)."""
        if not self.load_host_key():
            return

        port = self.protocol_config.get('port', 2222)
        host = '0.0.0.0'

        self.server_socket = None

        try:
            # Create TCP socket
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # Set timeout to allow checking self.running periodically
            self.server_socket.settimeout(1.0)

            self.server_socket.bind((host, port))
            self.server_socket.listen(100)

            print(f"[SSH-Paramiko] SSH Honeypot listening on {host}:{port}")
            self.running = True

            while self.running:
                try:
                    client_socket, client_addr = self.server_socket.accept()
                    client_ip = client_addr[0]

                    # Rate limiting check
                    if not self._check_rate_limit(client_ip):
                        print(f"[SECURITY] Rate limit exceeded for {client_ip}, dropping connection")
                        client_socket.close()
                        continue

                    print(f"[SSH-Paramiko] New connection from {client_ip}:{client_addr[1]}")

                    # Handle client in separate thread
                    client_thread = threading.Thread(
                        target=self._handle_client,
                        args=(client_socket, client_addr)
                    )
                    client_thread.daemon = True
                    client_thread.start()

                except socket.timeout:
                    # Timeout allows us to check self.running periodically
                    # Also clean up old rate limit entries
                    self._cleanup_rate_limits()
                    continue
                except Exception as e:
                    if self.running:
                        print(f"[SSH-Paramiko] Error accepting connection: {e}")
                        break

        except Exception as e:
            print(f"[SSH-Paramiko] ERROR: Failed to start server: {e}")
        finally:
            if self.server_socket:
                self.server_socket.close()
                print("[SSH-Paramiko] Server socket closed")

    def _check_rate_limit(self, ip: str) -> bool:
        """
        Check if IP is within rate limits.

        Args:
            ip: Client IP address

        Returns:
            True if connection is allowed, False if rate limit exceeded
        """
        import time

        current_time = time.time()

        # Initialize tracking for this IP if new
        if ip not in self.connection_counts:
            self.connection_counts[ip] = []

        # Remove timestamps outside the rate limit window
        self.connection_counts[ip] = [
            ts for ts in self.connection_counts[ip]
            if current_time - ts < self.RATE_LIMIT_WINDOW
        ]

        # Check if limit exceeded
        if len(self.connection_counts[ip]) >= self.MAX_CONNECTIONS_PER_IP:
            return False

        # Add current connection
        self.connection_counts[ip].append(current_time)
        return True

    def _cleanup_rate_limits(self):
        """Clean up old rate limit entries to prevent memory leaks."""
        import time

        current_time = time.time()

        # Remove IPs with no recent connections
        ips_to_remove = []
        for ip, timestamps in self.connection_counts.items():
            # Remove old timestamps
            recent_timestamps = [
                ts for ts in timestamps
                if current_time - ts < self.RATE_LIMIT_WINDOW
            ]

            if not recent_timestamps:
                ips_to_remove.append(ip)
            else:
                self.connection_counts[ip] = recent_timestamps

        for ip in ips_to_remove:
            del self.connection_counts[ip]

    def _handle_client(self, client_socket, client_addr):
        """Handle a client connection."""
        session_id = None

        try:
            # Create session
            import time
            session_id = f"{client_addr[0]}_{int(time.time() * 1000)}"

            # Log connection (synchronous)
            import asyncio
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(self.state_manager.create_session(client_addr[0]))
            loop.close()

            self.logger.log_connection(session_id, client_addr[0], client_addr[1], "SSH-Paramiko")

            # Create SSH transport
            transport = paramiko.Transport(client_socket)
            transport.local_version = self.protocol_config.get('banner', 'SSH-2.0-OpenSSH_7.6p1')

            # Add host key
            transport.add_server_key(self.host_key)

            # Create server interface
            server = SSHServerInterface(
                self.config_engine,
                self.state_manager,
                self.logger,
                session_id,
                client_addr[0]
            )

            # Start SSH server
            transport.start_server(server=server)

            # Wait for authentication
            channel = transport.accept(20)  # 20 second timeout

            if channel is None:
                print(f"[SSH-Paramiko] No channel opened from {client_addr[0]}")
                transport.close()
                return

            if server.authenticated_user is None:
                print(f"[SSH-Paramiko] Authentication failed from {client_addr[0]}")
                channel.close()
                transport.close()
                return

            print(f"[SSH-Paramiko] Authentication successful: {server.authenticated_user}@{client_addr[0]}")

            # Check if this is an exec request (SCP) or interactive shell
            if server.exec_command:
                # Handle exec command (SCP, remote command execution, etc.)
                self._handle_exec_command(channel, server.exec_command, server.authenticated_user, session_id, client_addr[0])
            else:
                # Start interactive shell
                self._interactive_shell(channel, server.authenticated_user, session_id, client_addr[0])

        except Exception as e:
            print(f"[SSH-Paramiko] Error handling client {client_addr[0]}: {e}")
            import traceback
            traceback.print_exc()
        finally:
            if session_id:
                # Close session
                import asyncio
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                loop.run_until_complete(self.state_manager.close_session(session_id))
                loop.close()

                self.logger.log_disconnect(session_id, "Connection closed")

    def _handle_exec_command(self, channel, command, username, session_id, client_ip):
        """
        Handle exec command (SCP, remote command execution, etc.).

        Args:
            channel: Paramiko channel
            command: Command to execute
            username: Authenticated username
            session_id: Session ID
            client_ip: Client IP address
        """
        try:
            from scp_handler import SCPReceiver, SCPProtocolHandler

            # Check if this is an SCP command
            receiver = SCPReceiver()
            parsed = receiver.parse_scp_command(command)

            if parsed:
                mode, target_path, is_recursive = parsed
                print(f"[SSH-Paramiko] SCP command detected: mode={mode}, path={target_path}, recursive={is_recursive}")

                if mode == 'sink':
                    # Receive files from attacker
                    import asyncio
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)

                    handler = SCPProtocolHandler(receiver, session_id, client_ip)
                    files_received = loop.run_until_complete(handler.handle_sink_mode(channel, target_path))

                    loop.close()

                    # Log all received files
                    for file_meta in files_received:
                        self.logger._log("SCP_FILE_UPLOAD", session_id, {
                            "filename": file_meta["original_filename"],
                            "size_bytes": file_meta["file_size_bytes"],
                            "sha256": file_meta["sha256"],
                            "md5": file_meta["md5"],
                            "target_path": target_path,
                            "quarantine_path": str(Path("quarantine") / "files" / file_meta["quarantine_filename"])
                        })

                        print(f"[SSH-Paramiko] SCP file received: {file_meta['original_filename']} ({file_meta['file_size_bytes']} bytes)")
                        print(f"                SHA256: {file_meta['sha256']}")

                elif mode == 'source':
                    # Attacker trying to download files - simulate empty/error
                    print(f"[SSH-Paramiko] SCP source mode (download) requested for: {target_path}")
                    self.logger._log("SCP_DOWNLOAD_ATTEMPT", session_id, {
                        "target_path": target_path,
                        "recursive": is_recursive
                    })
                    # Send error or pretend file doesn't exist
                    channel.send(b'\x01File not found\n')

            else:
                # Other exec commands - log and simulate
                print(f"[SSH-Paramiko] Exec command (non-SCP): {command}")
                self.logger._log("SSH_EXEC_COMMAND", session_id, {
                    "command": command
                })

                # Simulate command execution (send empty output and exit code 0)
                channel.send(b'')
                channel.send_exit_status(0)

            channel.close()

        except Exception as e:
            print(f"[SSH-Paramiko] Error handling exec command: {e}")
            import traceback
            traceback.print_exc()
            try:
                channel.send(b'\x02Fatal error\n')
                channel.close()
            except:
                pass

    def _interactive_shell(self, channel, username, session_id, client_ip):
        """
        Provide interactive shell session.

        Args:
            channel: Paramiko channel
            username: Authenticated username
            session_id: Session ID
            client_ip: Client IP address
        """
        try:
            # Create command processor
            command_processor = CommandProcessor(
                self.config_engine,
                self.state_manager,
                self.logger,
                self.dynamic_processor
            )

            # Send welcome message
            welcome = "Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-42-generic x86_64)\r\n\r\n"
            welcome += " * Documentation:  https://help.ubuntu.com\r\n"
            welcome += "\r\n"
            welcome += f"Last login: Mon Jan 15 12:34:56 2024 from 192.168.1.100\r\n"
            channel.send(welcome)

            print(f"[SSH-Paramiko] Starting shell session for {username}@{client_ip}")

            # Main command loop
            command_buffer = ""

            while True:
                # Send prompt
                context = command_processor._get_session_context(session_id)
                prompt = f"{context['user']}@{context['hostname']}:{context['cwd']}$ "
                channel.send(prompt)

                # Receive command character by character
                command_line = ""
                while True:
                    char = channel.recv(1)

                    if not char:
                        # Connection closed
                        print(f"[SSH-Paramiko] Connection closed by {client_ip}")
                        return

                    # Handle special characters
                    if char == b'\r' or char == b'\n':
                        # Enter pressed
                        channel.send(b'\r\n')
                        break
                    elif char == b'\x03':  # Ctrl+C
                        channel.send(b'^C\r\n')
                        command_line = ""
                        break
                    elif char == b'\x04':  # Ctrl+D (EOF)
                        command_line = "exit"
                        break
                    elif char == b'\x7f' or char == b'\x08':  # Backspace
                        if command_line:
                            command_line = command_line[:-1]
                            channel.send(b'\b \b')  # Erase character
                    elif char == b'\x1b':  # Escape (arrow keys, etc.)
                        # Read rest of escape sequence
                        try:
                            channel.recv(2)  # Discard escape sequence
                        except:
                            pass
                    elif 32 <= ord(char) <= 126:  # Printable ASCII
                        command_line += char.decode('utf-8', errors='ignore')
                        channel.send(char)  # Echo character

                command_line = command_line.strip()

                # Handle exit commands
                if command_line in ['exit', 'logout', 'quit']:
                    channel.send(b'logout\r\n')
                    print(f"[SSH-Paramiko] User {username} logged out from {client_ip}")
                    break

                if not command_line:
                    continue

                # Process command using CommandProcessor
                try:
                    # Run command processor in event loop
                    import asyncio
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)

                    output, latency_ms = loop.run_until_complete(
                        command_processor.process_command(session_id, command_line)
                    )

                    loop.close()

                    # Send output
                    if output:
                        # Convert line endings for terminal
                        output = output.replace('\n', '\r\n')
                        channel.send(output.encode('utf-8') + b'\r\n')

                except Exception as e:
                    print(f"[SSH-Paramiko] Error processing command '{command_line}': {e}")
                    channel.send(b'bash: command processing error\r\n')

            # Clean up
            command_processor.cleanup_session(session_id)

        except Exception as e:
            print(f"[SSH-Paramiko] Shell session error: {e}")
            import traceback
            traceback.print_exc()
        finally:
            channel.close()

    def stop_server(self):
        """Stop the SSH server."""
        print("[SSH-Paramiko] Stopping SSH server...")
        self.running = False

        # Close the server socket to unblock accept()
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass

        print("[SSH-Paramiko] SSH server stopped")
