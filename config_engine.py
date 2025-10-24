# config_engine.py

import json
import os
from typing import Dict, Any, Optional

class ConfigEngine:
    """
    Singleton Configuration Engine for the honeypot system.
    Loads, validates, and provides global access to configuration files.
    """

    _instance = None
    _initialized = False

    def __new__(cls):
        """Singleton pattern: Only one instance of ConfigEngine exists."""
        if cls._instance is None:
            cls._instance = super(ConfigEngine, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        """Initialize the configuration engine (only once due to singleton)."""
        if not ConfigEngine._initialized:
            self.configs: Dict[str, Dict[str, Any]] = {
                'commands': {},
                'files': {},
                'connection': {}
            }
            self.config_files = {
                'commands': 'config_commands.json',
                'files': 'config_files.json',
                'connection': 'config_connection.json'
            }
            ConfigEngine._initialized = True

    def load_configs(self) -> bool:
        """
        Loads all configuration files.
        Returns True if all configs loaded successfully, False otherwise.
        """
        success = True

        for config_type, filename in self.config_files.items():
            if not os.path.exists(filename):
                print(f"[WARN] Configuration file '{filename}' not found. Using empty config for '{config_type}'.")
                self.configs[config_type] = {}
                continue

            try:
                with open(filename, 'r', encoding='utf-8') as f:
                    self.configs[config_type] = json.load(f)
                print(f"[OK] Loaded configuration: {filename}")
            except json.JSONDecodeError as e:
                print(f"[ERROR] Invalid JSON in '{filename}': {e}")
                self.configs[config_type] = {}
                success = False
            except Exception as e:
                print(f"[ERROR] Failed to load '{filename}': {e}")
                self.configs[config_type] = {}
                success = False

        # Validate critical configurations
        if not self._validate_configs():
            print("[ERROR] Configuration validation failed.")
            return False

        return success

    def _validate_configs(self) -> bool:
        """
        Validates the loaded configurations for consistency and required fields.
        Returns True if validation passes, False otherwise.
        """
        # Validate connection config
        conn_config = self.configs.get('connection', {})
        if not conn_config:
            print("[WARN] No connection protocols configured.")
            return True  # Not critical, just a warning

        for protocol, details in conn_config.items():
            if 'port' not in details:
                print(f"[ERROR] Protocol '{protocol}' missing 'port' field.")
                return False

            if not isinstance(details['port'], int) or details['port'] < 1 or details['port'] > 65535:
                print(f"[ERROR] Protocol '{protocol}' has invalid port: {details['port']}")
                return False

        # Validate commands config structure
        commands_config = self.configs.get('commands', {})
        for cmd_name, cmd_details in commands_config.items():
            if not isinstance(cmd_details, dict):
                print(f"[WARN] Command '{cmd_name}' has invalid structure. Skipping.")
                continue

            # Check for required fields
            if 'output' not in cmd_details:
                print(f"[WARN] Command '{cmd_name}' missing 'output' field.")

        # Validate files config structure
        files_config = self.configs.get('files', {})
        for path, details in files_config.items():
            if not isinstance(details, dict):
                print(f"[WARN] File '{path}' has invalid structure. Skipping.")
                continue

            if 'type' not in details:
                print(f"[WARN] File '{path}' missing 'type' field.")

        return True

    def get_config(self, config_type: str) -> Dict[str, Any]:
        """
        Returns the entire configuration for a given type.

        Args:
            config_type: One of 'commands', 'files', 'connection'

        Returns:
            Dictionary containing the configuration, or empty dict if not found.
        """
        return self.configs.get(config_type, {})

    def get_command_info(self, command: str) -> Optional[Dict[str, Any]]:
        """
        Returns the configuration for a specific command.

        Args:
            command: The command name (e.g., 'ls', 'whoami')

        Returns:
            Dictionary with command configuration, or None if not found.
        """
        return self.configs.get('commands', {}).get(command)

    def get_file_info(self, path: str) -> Dict[str, Any]:
        """
        Returns the static configuration for a specific file/directory path.

        Args:
            path: The absolute path (e.g., '/etc/passwd')

        Returns:
            Dictionary with file configuration, or empty dict if not found.
        """
        return self.configs.get('files', {}).get(path, {})

    def get_protocol_config(self, protocol: str) -> Optional[Dict[str, Any]]:
        """
        Returns the configuration for a specific protocol.

        Args:
            protocol: The protocol name (e.g., 'ssh', 'ftp')

        Returns:
            Dictionary with protocol configuration, or None if not found.
        """
        return self.configs.get('connection', {}).get(protocol)

    def reload_configs(self) -> bool:
        """
        Reloads all configuration files from disk.
        Useful for updating configs without restarting the honeypot.

        Returns:
            True if reload was successful, False otherwise.
        """
        print("[INFO] Reloading all configuration files...")
        return self.load_configs()
