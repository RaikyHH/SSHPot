# network_handler.py

import asyncio
from typing import Dict, Type, Awaitable, Callable, Tuple
from base_handler import BaseProtocolHandler
from config_engine import ConfigEngine
from state_manager import StateManager
from forensic_logger import ForensicLogger

# Register all protocol emulators here as they are implemented.
# Example: 'ssh' : SSHSimulator (Implemented in Module 3)
PROTOCOL_HANDLERS: Dict[str, Type[BaseProtocolHandler]] = {}


class NetworkHandler:
    """
    Generic TCP/UDP handler that listens on configured ports
    and routes connections to the appropriate protocol emulator (Dispatcher).
    """

    def __init__(self, config_engine: ConfigEngine, state_manager: StateManager, logger: ForensicLogger):
        self.config = config_engine
        self.state_manager = state_manager
        self.logger = logger
        self._servers = []  # List of running asyncio.Server instances

    async def _handle_tcp_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Called by asyncio for each new TCP connection."""
        addr: Tuple[str, int] = writer.get_extra_info('peername')
        local_port = writer.get_extra_info('sockname')[1]

        print(f"[CONN] New connection from {addr[0]}:{addr[1]} on local port {local_port}")

        # 1. Protocol identification based on port
        protocol_type = self._get_protocol_by_port(local_port)

        if protocol_type not in PROTOCOL_HANDLERS:
            print(f"[ERROR] No handler found for protocol/port {local_port}. Closing connection.")
            writer.close()
            await writer.wait_closed()
            return

        # 2. Dispatching to protocol emulation
        HandlerClass = PROTOCOL_HANDLERS[protocol_type]
        handler = HandlerClass(reader, writer, self.config, self.state_manager, self.logger)

        try:
            await handler.run_emulation()
        except ConnectionResetError:
            await handler._close_connection(reason="Connection Reset by Client")
        except asyncio.CancelledError:
            await handler._close_connection(reason="Task Cancelled/Shutdown")
        except Exception as e:
            print(f"[ERROR] Unexpected error in handler {protocol_type}: {e}")
            await handler._close_connection(reason=f"Internal Error: {type(e).__name__}")


    def _get_protocol_by_port(self, port: int) -> str | None:
        """Finds the protocol by port in the configuration."""
        conn_config = self.config.get_config('connection')
        for protocol_name, details in conn_config.items():
            if details.get('port') == port:
                return protocol_name
        return None

    async def start_server(self):
        """Starts all configured servers (TCP and potentially UDP)."""
        conn_config = self.config.get_config('connection')

        if not conn_config:
            print("[WARN] No connection protocols defined in configuration.")
            return

        print("\n[INFO] Initializing network handler...")

        # Start TCP servers for each configured protocol
        for protocol_name, details in conn_config.items():
            if 'port' in details and protocol_name in PROTOCOL_HANDLERS:
                port = details['port']
                try:
                    server = await asyncio.start_server(
                        self._handle_tcp_connection,
                        '0.0.0.0',  # Listen on all interfaces
                        port
                    )
                    self._servers.append(server)
                    print(f"   [OK] Starting {protocol_name.upper()} emulation on TCP port {port}")
                except Exception as e:
                    print(f"   [ERROR] Could not start server on port {port} for {protocol_name}: {e}")
            else:
                print(f"   [WARN] Protocol '{protocol_name}' is configured, but no matching handler registered.")

        if self._servers:
            # Wait for all server tasks
            await asyncio.gather(*(server.serve_forever() for server in self._servers))

    async def stop_server(self):
        """Stops all running servers gracefully."""
        for server in self._servers:
            server.close()
            await server.wait_closed()
        print("[INFO] All network servers stopped.")