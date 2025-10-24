# main.py

import asyncio
import os
import json

from config_engine import ConfigEngine
from state_manager import StateManager
from forensic_logger import ForensicLogger
from monitoring import console_monitor
from ssh_server_paramiko import SSHHoneypotServer
from dynamic_values import DynamicValueProcessor


async def main():
    """Main function of the honeypot system."""

    # 1. Load configuration
    config_engine = ConfigEngine()
    if not config_engine.load_configs():
        print("[CRITICAL] Failed to load configurations. Exiting.")
        return

    # 2. Initialize state manager and logger
    state_manager = StateManager(db_path='honeypot_state.db')
    logger = ForensicLogger()

    # 3. Initialize dynamic value processor
    dynamic_processor = DynamicValueProcessor()

    # 4. Initialize SSH Honeypot Server (Paramiko-based, full SSH protocol)
    ssh_server = SSHHoneypotServer(config_engine, state_manager, logger, dynamic_processor)
    ssh_task = asyncio.create_task(ssh_server.start_server())

    # 4. Start console monitor
    monitor_task = asyncio.create_task(console_monitor(state_manager, logger))

    print("\n[INFO] SSHPot Honeypot started with full SSH-2.0 support (Paramiko)")
    print("[INFO] Compatible with PuTTY, OpenSSH, and all SSH clients")

    try:
        # Run both main tasks in parallel
        await asyncio.gather(ssh_task, monitor_task)

    except asyncio.CancelledError:
        print("\n[INFO] Shutdown initiated.")
    finally:
        # Clean shutdown
        monitor_task.cancel()
        ssh_server.stop_server()
        print("[INFO] Shutdown completed.")


if __name__ == "__main__":
    def setup_dummy_configs():
        """Creates dummy configuration files if they don't exist."""
        if not os.path.exists('config_commands.json'):
            commands_data = {
                "whoami": {"output": "root", "latency_ms": [50, 150], "state_change": None},
                "pwd": {"output": "/root", "latency_ms": [30, 80], "state_change": None},
                "ls": {"output": "dynamic", "latency_ms": [40, 120], "state_change": None}
            }
            files_data = {
                "/etc/passwd": {"type": "file", "content": "root:x:0:0:root:/root:/bin/bash\n", "perms": "rw-r--r--"},
                "/root": {"type": "dir", "perms": "rwx------"},
                "/tmp": {"type": "dir", "perms": "rwxrwxrwt"}
            }
            connection_data = {
                "ssh": {"port": 2222, "banner": "SSH-2.0-OpenSSH_7.6p1", "users": {"root": "toor", "admin": "admin"}}
            }

            with open('config_commands.json', 'w', encoding='utf-8') as f:
                json.dump(commands_data, f, indent=4)
            with open('config_files.json', 'w', encoding='utf-8') as f:
                json.dump(files_data, f, indent=4)
            with open('config_connection.json', 'w', encoding='utf-8') as f:
                json.dump(connection_data, f, indent=4)
            print("[INFO] Created default configuration files.")

    setup_dummy_configs()

    try:
        # Use asyncio.run() for better cross-platform compatibility (Python 3.7+)
        # This handles signal handling automatically on both Windows and Unix
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[INFO] Honeypot stopped by user.")