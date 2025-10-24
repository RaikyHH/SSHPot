# monitoring.py

import asyncio
import os
from typing import TYPE_CHECKING
# TYPE_CHECKING prevents circular dependencies during type hinting
if TYPE_CHECKING:
    from state_manager import StateManager
    from forensic_logger import ForensicLogger

# ANSI Escape Codes for console formatting
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RED = '\033[91m'
ENDC = '\033[0m'
BOLD = '\033[1m'

async def console_monitor(state_manager: 'StateManager', logger: 'ForensicLogger'):
    """Updates the honeypot console output in real-time."""

    while True:
        # Clear the console (works on most systems)
        os.system('cls' if os.name == 'nt' else 'clear')

        print(f"{BOLD}{GREEN}=== HONEYPOT STATUS MONITOR ==={ENDC}")

        # 1. Statistical Overview
        active_count = state_manager.get_active_sessions_count()
        print(f"\n{BOLD}{BLUE}--- ACTIVE SESSIONS ---{ENDC}")
        print(f"  Attackers: {active_count} {'(HIGH ACTIVITY!)' if active_count > 5 else ''}")
        print(f"  Total Log Entries: (Not implemented)")

        # 2. Recent Activity
        print(f"\n{BOLD}{BLUE}--- RECENT COMMANDS (Last {logger.max_commands}) ---{ENDC}")
        if not logger.last_commands:
            print(f"  {YELLOW}Waiting for first activity...{ENDC}")
        else:
            for cmd in logger.last_commands:
                print(f"  {cmd['time']} | {cmd['session']:<15} | {YELLOW}CMD:{ENDC} {cmd['command']}")

        # 3. Status
        print(f"\n{BOLD}{BLUE}--- SYSTEM STATUS ---{ENDC}")
        print(f"  Core: {GREEN}Running{ENDC}")
        print(f"  Logging: {GREEN}Active{ENDC} ({logger.log_file})")

        # Update frequency
        await asyncio.sleep(2)