# command_processor.py

import asyncio
import random
import time
from typing import Dict, Any, List, Optional, Tuple
from config_engine import ConfigEngine
from state_manager import StateManager
from forensic_logger import ForensicLogger
from dynamic_values import DynamicValueProcessor


class CommandProcessor:
    """
    Command parsing and simulation engine for the honeypot.
    Processes attacker commands and generates realistic output without executing anything.
    """

    def __init__(self, config: ConfigEngine, state_manager: StateManager, logger: ForensicLogger,
                 dynamic_processor: Optional[DynamicValueProcessor] = None):
        """Initialize the command processor with core components."""
        self.config = config
        self.state_manager = state_manager
        self.logger = logger
        self.dynamic_processor = dynamic_processor or DynamicValueProcessor()

        # Session-specific context (current working directory per session)
        self.session_contexts: Dict[str, Dict[str, Any]] = {}

    def _get_session_context(self, session_id: str) -> Dict[str, Any]:
        """Get or create session context (cwd, environment, etc.)."""
        if session_id not in self.session_contexts:
            self.session_contexts[session_id] = {
                'cwd': '/root',  # Default current working directory
                'user': 'root',
                'hostname': 'debian',
                'home': '/root'
            }
        return self.session_contexts[session_id]

    def _sanitize_path(self, path: str) -> str:
        """
        Sanitize path to prevent path traversal attacks.

        Args:
            path: Input path

        Returns:
            Sanitized path
        """
        # Remove null bytes
        path = path.replace('\x00', '')

        # Limit path length to prevent DoS
        if len(path) > 4096:
            path = path[:4096]

        # Remove dangerous characters but allow normal path chars
        # Allow: alphanumeric, /, ., -, _
        allowed_chars = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/-_.')
        path = ''.join(c for c in path if c in allowed_chars)

        return path

    def _resolve_path(self, session_id: str, path: str) -> str:
        """
        Resolve relative paths to absolute paths based on current working directory.

        Args:
            session_id: The session ID
            path: The path to resolve (can be relative or absolute)

        Returns:
            Absolute path (sanitized)
        """
        # Sanitize input first
        path = self._sanitize_path(path)

        if path.startswith('/'):
            # Normalize absolute path to prevent traversal
            parts = [p for p in path.split('/') if p and p != '.']
            normalized = []
            for part in parts:
                if part == '..':
                    if normalized:
                        normalized.pop()
                else:
                    normalized.append(part)
            return '/' + '/'.join(normalized) if normalized else '/'

        context = self._get_session_context(session_id)
        cwd = context['cwd']

        # Handle special cases
        if path == '.':
            return cwd
        if path == '..':
            if cwd == '/':
                return '/'
            return '/'.join(cwd.rstrip('/').split('/')[:-1]) or '/'
        if path.startswith('./'):
            path = path[2:]
        if path.startswith('../'):
            parent = '/'.join(cwd.rstrip('/').split('/')[:-1]) or '/'
            path_remainder = path[3:]
            combined = f"{parent}/{path_remainder}" if parent != '/' else f"/{path_remainder}"
            # Recursively resolve to handle multiple ../
            return self._resolve_path(session_id, combined)

        # Relative path - combine with cwd and normalize
        combined = f"{cwd.rstrip('/')}/{path}" if cwd != '/' else f"/{path}"
        return self._resolve_path(session_id, combined)

    def _sanitize_input(self, text: str, max_length: int = 8192) -> str:
        """
        Sanitize user input to prevent injection attacks.

        Args:
            text: Input text
            max_length: Maximum allowed length

        Returns:
            Sanitized text
        """
        # Limit length to prevent DoS
        if len(text) > max_length:
            text = text[:max_length]

        # Remove null bytes and other control characters except newline/tab
        text = ''.join(c for c in text if c.isprintable() or c in '\n\t')

        return text

    async def process_command(self, session_id: str, command_line: str) -> Tuple[str, int]:
        """
        Process a command and return the output and latency.

        Args:
            session_id: The attacker session ID
            command_line: The full command line string

        Returns:
            Tuple of (output_string, latency_ms)
        """
        start_time = time.time()

        # Sanitize input
        command_line = self._sanitize_input(command_line)
        command_line = command_line.strip()

        if not command_line:
            return ("", 0)

        parts = command_line.split()
        command = parts[0]
        args = parts[1:] if len(parts) > 1 else []

        # Check if command is configured
        cmd_config = self.config.get_command_info(command)

        # Simulate latency
        if cmd_config and 'latency_ms' in cmd_config:
            latency_range = cmd_config['latency_ms']
            if isinstance(latency_range, list) and len(latency_range) == 2:
                latency_ms = random.randint(latency_range[0], latency_range[1])
            else:
                latency_ms = 50
        else:
            latency_ms = random.randint(30, 100)

        await asyncio.sleep(latency_ms / 1000.0)

        # Process command
        output = await self._execute_command(session_id, command, args, cmd_config)

        # Process dynamic values in output if command has dynamic_values flag
        if cmd_config and cmd_config.get('dynamic_values', False):
            output = self.dynamic_processor.process(output, session_id)

        # Log the command execution
        elapsed_ms = int((time.time() - start_time) * 1000)
        self.logger.log_command(
            session_id,
            command_line,
            len(output),
            elapsed_ms,
            "SUCCESS" if output and not output.startswith("bash:") else "ERROR"
        )

        return (output, elapsed_ms)

    async def _execute_command(self, session_id: str, command: str, args: List[str],
                               cmd_config: Optional[Dict[str, Any]]) -> str:
        """
        Execute (simulate) a command and return its output.

        Args:
            session_id: Session ID
            command: Command name
            args: Command arguments
            cmd_config: Command configuration from config_commands.json

        Returns:
            Command output as string
        """
        # Command routing - try built-in handlers first
        handler_map = {
            'whoami': self._cmd_whoami,
            'pwd': self._cmd_pwd,
            'hostname': self._cmd_hostname,
            'uname': self._cmd_uname,
            'id': self._cmd_id,
            'date': self._cmd_date,
            'cd': self._cmd_cd,
            'ls': self._cmd_ls,
            'dir': self._cmd_ls,  # Alias for ls
            'cat': self._cmd_cat,
            'more': self._cmd_cat,  # Simplified
            'less': self._cmd_cat,  # Simplified
            'head': self._cmd_head,
            'tail': self._cmd_tail,
            'touch': self._cmd_touch,
            'rm': self._cmd_rm,
            'mkdir': self._cmd_mkdir,
            'rmdir': self._cmd_rmdir,
            'echo': self._cmd_echo,
            'ps': self._cmd_ps,
            'w': self._cmd_w,
            'who': self._cmd_who,
            'ifconfig': self._cmd_ifconfig,
            'netstat': self._cmd_netstat,
            'su': self._cmd_su,
            'sudo': self._cmd_sudo,
        }

        # Check if we have a handler for this command
        if command in handler_map:
            return await handler_map[command](session_id, args, cmd_config)

        # If command is in config but no handler, use static output
        # (dynamic values will be processed by the caller)
        if cmd_config and 'output' in cmd_config:
            return cmd_config['output']

        # Command not found
        return f"bash: {command}: command not found"

    # ============================================================================
    # STATIC COMMAND HANDLERS (No filesystem interaction)
    # ============================================================================

    async def _cmd_whoami(self, session_id: str, args: List[str], config: Optional[Dict]) -> str:
        """Handle whoami command."""
        if config and 'output' in config:
            return config['output']
        context = self._get_session_context(session_id)
        return context['user']

    async def _cmd_pwd(self, session_id: str, args: List[str], config: Optional[Dict]) -> str:
        """Handle pwd command."""
        if config and 'output' in config and config['output'] != 'dynamic':
            return config['output']
        context = self._get_session_context(session_id)
        return context['cwd']

    async def _cmd_hostname(self, session_id: str, args: List[str], config: Optional[Dict]) -> str:
        """Handle hostname command."""
        if config and 'output' in config:
            return config['output']
        context = self._get_session_context(session_id)
        return context['hostname']

    async def _cmd_uname(self, session_id: str, args: List[str], config: Optional[Dict]) -> str:
        """Handle uname command."""
        if config and 'output' in config and config['output'] != 'dynamic':
            return config['output']

        if '-a' in args or '--all' in args:
            return "Linux debian 4.19.0-18-amd64 #1 SMP Debian 4.19.208-1 (2021-09-29) x86_64 GNU/Linux"
        elif '-r' in args or '--kernel-release' in args:
            return "4.19.0-18-amd64"
        elif '-v' in args or '--kernel-version' in args:
            return "#1 SMP Debian 4.19.208-1 (2021-09-29)"
        else:
            return "Linux"

    async def _cmd_id(self, session_id: str, args: List[str], config: Optional[Dict]) -> str:
        """Handle id command."""
        if config and 'output' in config and config['output'] != 'dynamic':
            return config['output']
        context = self._get_session_context(session_id)
        if context['user'] == 'root':
            return "uid=0(root) gid=0(root) groups=0(root)"
        else:
            return f"uid=1000({context['user']}) gid=1000({context['user']}) groups=1000({context['user']})"

    async def _cmd_date(self, session_id: str, args: List[str], config: Optional[Dict]) -> str:
        """Handle date command."""
        if config and 'output' in config and config['output'] != 'dynamic':
            return config['output']
        import datetime
        return datetime.datetime.now().strftime("%a %b %d %H:%M:%S %Z %Y")

    async def _cmd_ps(self, session_id: str, args: List[str], config: Optional[Dict]) -> str:
        """Handle ps command."""
        if config and 'output' in config and config['output'] != 'dynamic':
            return config['output']
        return """  PID TTY          TIME CMD
    1 ?        00:00:01 systemd
  234 ?        00:00:00 sshd
  235 pts/0    00:00:00 bash
  456 pts/0    00:00:00 ps"""

    async def _cmd_w(self, session_id: str, args: List[str], config: Optional[Dict]) -> str:
        """Handle w command."""
        if config and 'output' in config and config['output'] != 'dynamic':
            return config['output']
        context = self._get_session_context(session_id)
        return f""" 12:34:56 up 10 days, 3:21, 1 user, load average: 0.00, 0.01, 0.05
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
{context['user']}     pts/0    192.168.1.100    12:30    0.00s  0.05s  0.00s w"""

    async def _cmd_who(self, session_id: str, args: List[str], config: Optional[Dict]) -> str:
        """Handle who command."""
        if config and 'output' in config and config['output'] != 'dynamic':
            return config['output']
        context = self._get_session_context(session_id)
        return f"{context['user']}     pts/0        2024-01-15 12:30 (192.168.1.100)"

    async def _cmd_ifconfig(self, session_id: str, args: List[str], config: Optional[Dict]) -> str:
        """Handle ifconfig command."""
        if config and 'output' in config and config['output'] != 'dynamic':
            return config['output']
        return """eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.1.50  netmask 255.255.255.0  broadcast 192.168.1.255
        inet6 fe80::20c:29ff:fe12:3456  prefixlen 64  scopeid 0x20<link>
        ether 00:0c:29:12:34:56  txqueuelen 1000  (Ethernet)"""

    async def _cmd_netstat(self, session_id: str, args: List[str], config: Optional[Dict]) -> str:
        """Handle netstat command."""
        if config and 'output' in config and config['output'] != 'dynamic':
            return config['output']
        return """Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN
tcp        0      0 192.168.1.50:22         192.168.1.100:54321     ESTABLISHED"""

    async def _cmd_su(self, session_id: str, args: List[str], config: Optional[Dict]) -> str:
        """Handle su command - switch user (simulated)."""
        if config and 'output' in config and config['output'] != 'dynamic':
            return config['output']

        # In a honeypot, we simulate authentication failure
        # This is more realistic than asking for password since we can't interactively wait for it
        target_user = args[0] if args else 'root'
        context = self._get_session_context(session_id)

        # If trying to su to the same user, fail
        if target_user == context['user']:
            return ""  # No output, just return to prompt

        # Otherwise, simulate authentication failure
        return "su: Authentication failure"

    async def _cmd_sudo(self, session_id: str, args: List[str], config: Optional[Dict]) -> str:
        """Handle sudo command - execute as root (simulated)."""
        if config and 'output' in config and config['output'] != 'dynamic':
            return config['output']

        if not args:
            return "usage: sudo -h | -K | -k | -V\nusage: sudo -v [-AknS] [-g group] [-h host] [-p prompt] [-u user]\nusage: sudo -l [-AknS] [-g group] [-h host] [-p prompt] [-U user] [-u user] [command]\nusage: sudo [-AbEHknPS] [-r role] [-t type] [-C num] [-g group] [-h host] [-p prompt] [-T timeout] [-u user] [VAR=value] [-i|-s] [<command>]"

        # Context: we're already root in most honeypot scenarios, so sudo would succeed
        context = self._get_session_context(session_id)
        if context['user'] == 'root':
            # Execute the command (recursively call process_command with the args)
            # For simplicity in honeypot, just return empty (command would execute silently)
            return ""
        else:
            # Non-root user trying sudo - ask for password and fail
            return "sudo: 3 incorrect password attempts"

    # ============================================================================
    # FILESYSTEM COMMANDS (Dynamic - interact with StateManager)
    # ============================================================================

    async def _cmd_cd(self, session_id: str, args: List[str], config: Optional[Dict]) -> str:
        """Handle cd command - changes current working directory."""
        if not args:
            # cd with no args goes to home
            context = self._get_session_context(session_id)
            context['cwd'] = context['home']
            return ""

        target = args[0]
        abs_path = self._resolve_path(session_id, target)

        # Check if directory exists
        file_state = await self.state_manager.resolve_file_state(session_id, abs_path)

        if not file_state.get('exists'):
            return f"bash: cd: {target}: No such file or directory"

        if file_state.get('type') != 'dir':
            return f"bash: cd: {target}: Not a directory"

        # Update context
        context = self._get_session_context(session_id)
        context['cwd'] = abs_path
        return ""

    async def _cmd_ls(self, session_id: str, args: List[str], config: Optional[Dict]) -> str:
        """Handle ls command - list directory contents."""
        # Parse flags from arguments
        show_hidden = False
        long_format = False
        target_path = None

        for arg in args:
            if arg.startswith('-') and arg != '-':
                # Parse combined flags (e.g., -la, -al, -lah)
                flags = arg[1:]  # Remove leading dash
                if 'a' in flags or arg == '--all':
                    show_hidden = True
                if 'l' in flags or arg == '--format=long':
                    long_format = True
            elif not arg.startswith('-'):
                target_path = arg
                break

        if target_path is None:
            context = self._get_session_context(session_id)
            target_path = context['cwd']
        else:
            target_path = self._resolve_path(session_id, target_path)

        # Get all files from static config
        all_files = self.config.get_config('files')

        # Get dynamic changes for this session
        changes = await self.state_manager.get_file_changes(session_id)

        # Build list of files in target directory
        files_in_dir = []

        # Add static files
        for path, info in all_files.items():
            if self._is_in_directory(path, target_path):
                basename = path.split('/')[-1] if path != target_path else path
                if basename:
                    # Skip hidden files unless -a flag is used
                    if not show_hidden and basename.startswith('.'):
                        continue

                    file_state = await self.state_manager.resolve_file_state(session_id, path)
                    if file_state.get('exists'):
                        files_in_dir.append(basename)

        # Add dynamically created files
        for change in changes:
            path = change['path']
            if change['action'] != 'delete' and self._is_in_directory(path, target_path):
                basename = path.split('/')[-1]

                # Skip hidden files unless -a flag is used
                if not show_hidden and basename.startswith('.'):
                    continue

                if basename and basename not in files_in_dir:
                    files_in_dir.append(basename)

        # Add . and .. when showing hidden files
        if show_hidden:
            files_in_dir.insert(0, '..')
            files_in_dir.insert(0, '.')

        if not files_in_dir:
            return ""

        # Format output
        if long_format:
            # Long format
            output_lines = []
            for filename in sorted(files_in_dir):
                if filename in ['.', '..']:
                    # Special handling for . and ..
                    output_lines.append(f"drwxr-xr-x 1 root root  4096 Jan 15 12:00 {filename}")
                else:
                    full_path = f"{target_path.rstrip('/')}/{filename}"
                    file_state = await self.state_manager.resolve_file_state(session_id, full_path)
                    perms = file_state.get('perms', 'rw-r--r--')
                    ftype = 'd' if file_state.get('type') == 'dir' else '-'
                    output_lines.append(f"{ftype}{perms} 1 root root  4096 Jan 15 12:00 {filename}")
            return "\n".join(output_lines)
        else:
            # Simple format
            return "  ".join(sorted(files_in_dir))

    def _is_in_directory(self, file_path: str, dir_path: str) -> bool:
        """Check if file_path is directly in dir_path (not subdirectories)."""
        if dir_path == '/':
            # Root directory - check for top-level items
            return file_path.count('/') == 1 and file_path != '/'
        else:
            parent = '/'.join(file_path.rstrip('/').split('/')[:-1])
            return parent == dir_path.rstrip('/')

    async def _cmd_cat(self, session_id: str, args: List[str], config: Optional[Dict]) -> str:
        """Handle cat command - display file contents."""
        if not args:
            return "cat: missing file operand"

        file_path = self._resolve_path(session_id, args[0])
        file_state = await self.state_manager.resolve_file_state(session_id, file_path)

        if not file_state.get('exists'):
            return f"cat: {args[0]}: No such file or directory"

        if file_state.get('type') == 'dir':
            return f"cat: {args[0]}: Is a directory"

        return file_state.get('content', '')

    async def _cmd_head(self, session_id: str, args: List[str], config: Optional[Dict]) -> str:
        """Handle head command - display first lines of file."""
        if not args:
            return "head: missing file operand"

        file_path = self._resolve_path(session_id, args[0])
        file_state = await self.state_manager.resolve_file_state(session_id, file_path)

        if not file_state.get('exists'):
            return f"head: cannot open '{args[0]}': No such file or directory"

        content = file_state.get('content', '')
        lines = content.split('\n')[:10]  # First 10 lines
        return '\n'.join(lines)

    async def _cmd_tail(self, session_id: str, args: List[str], config: Optional[Dict]) -> str:
        """Handle tail command - display last lines of file."""
        if not args:
            return "tail: missing file operand"

        file_path = self._resolve_path(session_id, args[0])
        file_state = await self.state_manager.resolve_file_state(session_id, file_path)

        if not file_state.get('exists'):
            return f"tail: cannot open '{args[0]}': No such file or directory"

        content = file_state.get('content', '')
        lines = content.split('\n')[-10:]  # Last 10 lines
        return '\n'.join(lines)

    # ============================================================================
    # STATE-CHANGING COMMANDS (Modify virtual filesystem)
    # ============================================================================

    async def _cmd_touch(self, session_id: str, args: List[str], config: Optional[Dict]) -> str:
        """Handle touch command - create empty file."""
        if not args:
            return "touch: missing file operand"

        file_path = self._resolve_path(session_id, args[0])

        # Check if file already exists
        file_state = await self.state_manager.resolve_file_state(session_id, file_path)

        if file_state.get('exists'):
            # File exists, just update timestamp (we don't track that, so do nothing)
            return ""
        else:
            # Create new file
            await self.state_manager.track_file_change(session_id, file_path, 'create', '')
            self.logger.log_state_change(session_id, file_path, 'create')
            return ""

    async def _cmd_rm(self, session_id: str, args: List[str], config: Optional[Dict]) -> str:
        """Handle rm command - remove file."""
        if not args:
            return "rm: missing operand"

        # Parse flags
        recursive = False
        force = False
        target_path = None

        for arg in args:
            if arg.startswith('-') and arg != '-':
                flags = arg[1:]  # Remove leading dash
                if 'r' in flags or 'R' in flags:
                    recursive = True
                if 'f' in flags:
                    force = True
            elif not arg.startswith('-'):
                target_path = arg
                break

        if target_path is None:
            return "rm: missing operand"

        file_path = self._resolve_path(session_id, target_path)
        file_state = await self.state_manager.resolve_file_state(session_id, file_path)

        if not file_state.get('exists'):
            if force:
                # -f flag suppresses errors for non-existent files
                return ""
            return f"rm: cannot remove '{target_path}': No such file or directory"

        if file_state.get('type') == 'dir' and not recursive:
            return f"rm: cannot remove '{target_path}': Is a directory"

        # Delete the file
        await self.state_manager.track_file_change(session_id, file_path, 'delete', None)
        self.logger.log_state_change(session_id, file_path, 'delete')
        return ""

    async def _cmd_mkdir(self, session_id: str, args: List[str], config: Optional[Dict]) -> str:
        """Handle mkdir command - create directory."""
        if not args:
            return "mkdir: missing operand"

        # Parse flags
        create_parents = False
        target_path = None

        for arg in args:
            if arg.startswith('-') and arg != '-':
                flags = arg[1:]  # Remove leading dash
                if 'p' in flags:
                    create_parents = True
            elif not arg.startswith('-'):
                target_path = arg
                break

        if target_path is None:
            return "mkdir: missing operand"

        dir_path = self._resolve_path(session_id, target_path)
        file_state = await self.state_manager.resolve_file_state(session_id, dir_path)

        if file_state.get('exists'):
            if create_parents:
                # -p flag suppresses error if directory exists
                return ""
            return f"mkdir: cannot create directory '{target_path}': File exists"

        # Create directory (in honeypot, we don't actually validate parent exists)
        await self.state_manager.track_file_change(session_id, dir_path, 'create', '')
        self.logger.log_state_change(session_id, dir_path, 'create_dir')
        return ""

    async def _cmd_rmdir(self, session_id: str, args: List[str], config: Optional[Dict]) -> str:
        """Handle rmdir command - remove directory."""
        if not args:
            return "rmdir: missing operand"

        dir_path = self._resolve_path(session_id, args[0])
        file_state = await self.state_manager.resolve_file_state(session_id, dir_path)

        if not file_state.get('exists'):
            return f"rmdir: failed to remove '{args[0]}': No such file or directory"

        if file_state.get('type') != 'dir':
            return f"rmdir: failed to remove '{args[0]}': Not a directory"

        # Delete directory
        await self.state_manager.track_file_change(session_id, dir_path, 'delete', None)
        self.logger.log_state_change(session_id, dir_path, 'delete_dir')
        return ""

    async def _cmd_echo(self, session_id: str, args: List[str], config: Optional[Dict]) -> str:
        """Handle echo command - print text or redirect to file."""
        if not args:
            return ""

        # Check for output redirection
        if '>' in args:
            redirect_idx = args.index('>')
            text = ' '.join(args[:redirect_idx])
            if redirect_idx + 1 < len(args):
                file_path = self._resolve_path(session_id, args[redirect_idx + 1])
                # Write to file
                await self.state_manager.track_file_change(session_id, file_path, 'modify', text)
                self.logger.log_state_change(session_id, file_path, 'write')
                return ""
            else:
                return "bash: syntax error near unexpected token `>'"
        elif '>>' in args:
            redirect_idx = args.index('>>')
            text = ' '.join(args[:redirect_idx])
            if redirect_idx + 1 < len(args):
                file_path = self._resolve_path(session_id, args[redirect_idx + 1])
                # Append to file (simplified - we just modify)
                file_state = await self.state_manager.resolve_file_state(session_id, file_path)
                existing = file_state.get('content', '') if file_state.get('exists') else ''
                new_content = existing + '\n' + text if existing else text
                await self.state_manager.track_file_change(session_id, file_path, 'modify', new_content)
                self.logger.log_state_change(session_id, file_path, 'append')
                return ""
            else:
                return "bash: syntax error near unexpected token `>>'"
        else:
            # Just echo the text
            return ' '.join(args)

    def cleanup_session(self, session_id: str):
        """Clean up session context when session ends."""
        if session_id in self.session_contexts:
            del self.session_contexts[session_id]
