"""
File Operations Handler for SSHPot Honeypot

This module processes file operation commands declared in config_commands.json
and applies them to the per-session virtual filesystem via StateManager.

Defensive Security Tool - Does NOT execute actual commands
"""

import asyncio
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from pathlib import PurePosixPath
import shlex


@dataclass
class ParsedCommand:
    """Represents a parsed command with its components"""
    command: str
    args: List[str]
    flags: Dict[str, bool]
    redirect_op: Optional[str] = None
    redirect_target: Optional[str] = None
    args_before_redirect: List[str] = None

    def __post_init__(self):
        if self.args_before_redirect is None:
            self.args_before_redirect = self.args.copy()


@dataclass
class FileOperationResult:
    """Result of a file operation"""
    success: bool
    output: str = ""
    error: str = ""
    state_changes: List[Dict[str, Any]] = None

    def __post_init__(self):
        if self.state_changes is None:
            self.state_changes = []


class FileOperationHandler:
    """
    Handles file operations defined in command configurations
    Works with StateManager to apply changes to virtual filesystem
    """

    def __init__(self, state_manager, config_engine):
        """
        Args:
            state_manager: IStateManager implementation
            config_engine: ConfigEngine instance
        """
        self.state_manager = state_manager
        self.config_engine = config_engine

    def parse_command_line(self, command_line: str) -> ParsedCommand:
        """
        Parse a command line into components

        Args:
            command_line: Full command string (e.g., "echo test > file.txt")

        Returns:
            ParsedCommand with parsed components
        """
        # Handle redirects
        redirect_op = None
        redirect_target = None
        base_command = command_line

        for op in ['>>', '>']:
            if op in command_line:
                parts = command_line.split(op, 1)
                base_command = parts[0].strip()
                redirect_target = parts[1].strip().split()[0] if len(parts) > 1 else None
                redirect_op = op
                break

        # Parse the base command
        try:
            tokens = shlex.split(base_command)
        except ValueError:
            # Handle malformed quotes
            tokens = base_command.split()

        if not tokens:
            return ParsedCommand(command="", args=[], flags={})

        command = tokens[0]
        args = []
        flags = {}

        # Separate flags from arguments
        i = 1
        while i < len(tokens):
            token = tokens[i]
            if token.startswith('-'):
                flags[token] = True
            else:
                args.append(token)
            i += 1

        # Get args before redirect
        args_before_redirect = []
        if redirect_op and redirect_target:
            # Everything before redirect operator
            try:
                pre_redirect = shlex.split(base_command)
                args_before_redirect = [t for t in pre_redirect[1:] if not t.startswith('-')]
            except ValueError:
                args_before_redirect = args.copy()
        else:
            args_before_redirect = args.copy()

        return ParsedCommand(
            command=command,
            args=args,
            flags=flags,
            redirect_op=redirect_op,
            redirect_target=redirect_target,
            args_before_redirect=args_before_redirect
        )

    def resolve_path(self, path: str, current_dir: str = "/root") -> str:
        """
        Resolve a relative or absolute path

        Args:
            path: Path to resolve
            current_dir: Current working directory

        Returns:
            Absolute path string
        """
        if path.startswith('/'):
            return str(PurePosixPath(path))
        else:
            return str(PurePosixPath(current_dir) / path)

    async def validate_operation(
        self,
        session_id: str,
        operation_config: Dict,
        parsed_cmd: ParsedCommand,
        current_dir: str
    ) -> Tuple[bool, str]:
        """
        Validate if a file operation can be performed

        Args:
            session_id: Session identifier
            operation_config: File operation configuration from command config
            parsed_cmd: Parsed command
            current_dir: Current working directory

        Returns:
            Tuple of (is_valid, error_message)
        """
        validates = operation_config.get('validates', [])
        arg_mapping = operation_config.get('arg_mapping', {})

        # Check if required args are present
        if operation_config.get('requires_args', False):
            required_args = len(arg_mapping)
            if len(parsed_cmd.args) < required_args:
                return False, f"{parsed_cmd.command}: missing operand"

        # Check for flags that skip validation
        flags_config = operation_config.get('flags', {})
        for flag, flag_opts in flags_config.items():
            if flag in parsed_cmd.flags and flag_opts.get('skip_validation', False):
                return True, ""  # Skip all validations

        # Perform validations
        for validation in validates:
            if validation == "exists" or validation == "source_exists":
                # Check if source file exists
                target_arg = arg_mapping.get('target', arg_mapping.get('source', 0))
                if target_arg < len(parsed_cmd.args):
                    path = self.resolve_path(parsed_cmd.args[target_arg], current_dir)
                    file_state = await self.state_manager.resolve_file_state(session_id, path)
                    if not file_state:
                        return False, f"{parsed_cmd.command}: cannot access '{parsed_cmd.args[target_arg]}': No such file or directory"

            elif validation == "is_dir":
                target_arg = arg_mapping.get('target', 0)
                if target_arg < len(parsed_cmd.args):
                    path = self.resolve_path(parsed_cmd.args[target_arg], current_dir)
                    file_state = await self.state_manager.resolve_file_state(session_id, path)
                    if file_state and file_state.get('type') != 'dir':
                        return False, f"{parsed_cmd.command}: '{parsed_cmd.args[target_arg]}': Not a directory"

            elif validation == "is_file":
                target_arg = arg_mapping.get('target', 0)
                if target_arg < len(parsed_cmd.args):
                    path = self.resolve_path(parsed_cmd.args[target_arg], current_dir)
                    file_state = await self.state_manager.resolve_file_state(session_id, path)
                    if file_state and file_state.get('type') != 'file':
                        return False, f"{parsed_cmd.command}: '{parsed_cmd.args[target_arg]}': Is a directory"

            elif validation == "parent_exists":
                target_arg = arg_mapping.get('target', 0)
                if target_arg < len(parsed_cmd.args):
                    path = self.resolve_path(parsed_cmd.args[target_arg], current_dir)
                    parent_path = str(PurePosixPath(path).parent)
                    parent_state = await self.state_manager.resolve_file_state(session_id, parent_path)
                    if not parent_state:
                        return False, f"{parsed_cmd.command}: cannot create directory '{parsed_cmd.args[target_arg]}': No such file or directory"

            elif validation == "is_empty":
                # Check if directory is empty
                target_arg = arg_mapping.get('target', 0)
                if target_arg < len(parsed_cmd.args):
                    path = self.resolve_path(parsed_cmd.args[target_arg], current_dir)
                    # For simplicity, we'll assume empty unless files exist with this path as parent
                    # This would need integration with a more complete filesystem listing
                    pass

        return True, ""

    async def execute_file_operation(
        self,
        session_id: str,
        command_name: str,
        parsed_cmd: ParsedCommand,
        current_dir: str = "/root"
    ) -> FileOperationResult:
        """
        Execute a file operation based on command configuration

        Args:
            session_id: Session identifier
            command_name: Name of the command
            parsed_cmd: Parsed command
            current_dir: Current working directory

        Returns:
            FileOperationResult with outcome and state changes
        """
        # Get command configuration
        commands_config = self.config_engine.get_config('commands')
        if command_name not in commands_config:
            return FileOperationResult(success=False, error=f"{command_name}: command not found")

        cmd_config = commands_config[command_name]
        file_ops = cmd_config.get('file_operations')

        if not file_ops:
            return FileOperationResult(success=False, error=f"{command_name}: no file operations defined")

        # Validate operation
        is_valid, error_msg = await self.validate_operation(session_id, file_ops, parsed_cmd, current_dir)
        if not is_valid:
            return FileOperationResult(success=False, error=error_msg)

        # Execute based on operation type
        operation_type = file_ops.get('type')
        effect = file_ops.get('effect', {})
        arg_mapping = file_ops.get('arg_mapping', {})

        state_changes = []
        output = ""

        if operation_type == "create":
            # Handle touch, mkdir
            target_arg = arg_mapping.get('target', 0)
            if target_arg < len(parsed_cmd.args):
                path = self.resolve_path(parsed_cmd.args[target_arg], current_dir)
                file_type = effect.get('file_type', 'file')
                content = effect.get('content', '')

                await self.state_manager.track_file_change(
                    session_id, path, "create",
                    content=content,
                    metadata={'type': file_type}
                )
                state_changes.append({
                    'path': path,
                    'action': 'create',
                    'type': file_type
                })

        elif operation_type == "delete":
            # Handle rm, rmdir
            target_arg = arg_mapping.get('target', 0)
            if target_arg < len(parsed_cmd.args):
                path = self.resolve_path(parsed_cmd.args[target_arg], current_dir)

                await self.state_manager.track_file_change(
                    session_id, path, "delete"
                )
                state_changes.append({
                    'path': path,
                    'action': 'delete'
                })

        elif operation_type == "write":
            # Handle echo with redirect
            redirects = file_ops.get('redirects', {})
            if parsed_cmd.redirect_op and parsed_cmd.redirect_op in redirects:
                redirect_config = redirects[parsed_cmd.redirect_op]
                action = redirect_config.get('action', 'overwrite')

                path = self.resolve_path(parsed_cmd.redirect_target, current_dir)

                # Get content from args
                content = ' '.join(parsed_cmd.args_before_redirect)

                if action == "append":
                    # Get existing content
                    existing = await self.state_manager.resolve_file_state(session_id, path)
                    if existing:
                        content = existing.get('content', '') + '\n' + content

                    await self.state_manager.track_file_change(
                        session_id, path, "modify", content=content
                    )
                    state_changes.append({
                        'path': path,
                        'action': 'append',
                        'content': content
                    })
                else:  # overwrite
                    await self.state_manager.track_file_change(
                        session_id, path, "create", content=content
                    )
                    state_changes.append({
                        'path': path,
                        'action': 'overwrite',
                        'content': content
                    })
            else:
                # No redirect, just echo to stdout
                output = ' '.join(parsed_cmd.args)

        elif operation_type == "copy":
            # Handle cp
            source_arg = arg_mapping.get('source', 0)
            dest_arg = arg_mapping.get('destination', 1)

            if source_arg < len(parsed_cmd.args) and dest_arg < len(parsed_cmd.args):
                source_path = self.resolve_path(parsed_cmd.args[source_arg], current_dir)
                dest_path = self.resolve_path(parsed_cmd.args[dest_arg], current_dir)

                # Get source content
                source_state = await self.state_manager.resolve_file_state(session_id, source_path)
                if source_state:
                    content = source_state.get('content', '')
                    file_type = source_state.get('type', 'file')

                    await self.state_manager.track_file_change(
                        session_id, dest_path, "create",
                        content=content,
                        metadata={'type': file_type, 'copied_from': source_path}
                    )
                    state_changes.append({
                        'path': dest_path,
                        'action': 'copy',
                        'source': source_path
                    })

        elif operation_type == "move":
            # Handle mv
            source_arg = arg_mapping.get('source', 0)
            dest_arg = arg_mapping.get('destination', 1)

            if source_arg < len(parsed_cmd.args) and dest_arg < len(parsed_cmd.args):
                source_path = self.resolve_path(parsed_cmd.args[source_arg], current_dir)
                dest_path = self.resolve_path(parsed_cmd.args[dest_arg], current_dir)

                # Get source content
                source_state = await self.state_manager.resolve_file_state(session_id, source_path)
                if source_state:
                    content = source_state.get('content', '')
                    file_type = source_state.get('type', 'file')

                    # Create at destination
                    await self.state_manager.track_file_change(
                        session_id, dest_path, "create",
                        content=content,
                        metadata={'type': file_type, 'moved_from': source_path}
                    )
                    # Delete source
                    await self.state_manager.track_file_change(
                        session_id, source_path, "delete"
                    )
                    state_changes.append({
                        'path': dest_path,
                        'action': 'move',
                        'source': source_path
                    })
                    state_changes.append({
                        'path': source_path,
                        'action': 'delete'
                    })

        return FileOperationResult(
            success=True,
            output=output,
            state_changes=state_changes
        )

    async def process_command(
        self,
        session_id: str,
        command_line: str,
        current_dir: str = "/root"
    ) -> FileOperationResult:
        """
        Main entry point for processing a command with file operations

        Args:
            session_id: Session identifier
            command_line: Full command line string
            current_dir: Current working directory

        Returns:
            FileOperationResult with outcome
        """
        parsed = self.parse_command_line(command_line)

        if not parsed.command:
            return FileOperationResult(success=False, error="No command provided")

        return await self.execute_file_operation(
            session_id,
            parsed.command,
            parsed,
            current_dir
        )
