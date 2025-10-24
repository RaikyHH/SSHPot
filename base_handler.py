# base_handler.py

import asyncio
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Tuple

# Avoids circular dependencies during type hinting
if TYPE_CHECKING:
    from config_engine import ConfigEngine
    from state_manager import StateManager
    from forensic_logger import ForensicLogger

class BaseProtocolHandler(ABC):
    """
    Abstract base class for all protocol emulators (e.g. SSH, FTP).
    Defines the necessary interface and provides access to core components.
    """

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                 config_engine: 'ConfigEngine', state_manager: 'StateManager', logger: 'ForensicLogger'):
        """Initializes the handler with network streams and core components."""
        self.reader = reader
        self.writer = writer
        self.config = config_engine
        self.state_manager = state_manager
        self.logger = logger

        self.addr: Tuple[str, int] = writer.get_extra_info('peername')
        self.ip: str = self.addr[0]
        self.port: int = self.addr[1]

        self.session_id: str = None  # Assigned when emulation starts

    @abstractmethod
    async def run_emulation(self):
        """The main method that emulates the specific protocol."""
        pass

    async def _start_session(self, protocol_name: str):
        """Starts a new honeypot session and logs the connection establishment."""
        self.session_id = await self.state_manager.create_session(self.ip)
        self.logger.log_connection(self.session_id, self.ip, self.port, protocol_name)
        print(f"[INFO] New {protocol_name} session started: {self.session_id} from {self.ip}")

    async def _close_connection(self, reason: str = "Graceful"):
        """Closes the connection and logs the end of the session."""
        if self.session_id:
            await self.state_manager.close_session(self.session_id)
            self.logger.log_disconnect(self.session_id, reason)

        try:
            self.writer.close()
            await self.writer.wait_closed()
        except Exception as e:
            # Connection possibly already closed
            pass

        print(f"[INFO] Session ended: {self.session_id} ({self.ip}) - Reason: {reason}")