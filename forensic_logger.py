# forensic_logger.py

import json
import time
from typing import Dict, Any

class ForensicLogger:
    """
    Centralized forensic logging system for honeypot events.
    Logs all events in structured JSON-Lines format.
    """

    def __init__(self, log_file: str = 'honeypot_forensics.log'):
        self.log_file = log_file
        self.last_commands: list[Dict[str, Any]] = []
        self.max_commands = 20

    def _sanitize_for_log(self, text: str, max_length: int = 65536) -> str:
        """
        Sanitize text before logging to prevent log injection.

        Args:
            text: Text to sanitize
            max_length: Maximum allowed length

        Returns:
            Sanitized text
        """
        if not isinstance(text, str):
            text = str(text)

        # Limit length
        if len(text) > max_length:
            text = text[:max_length] + "...[TRUNCATED]"

        # Remove null bytes and non-printable characters except newlines/tabs
        text = ''.join(c for c in text if c.isprintable() or c in '\n\t')

        # Escape newlines to prevent log injection
        text = text.replace('\n', '\\n').replace('\r', '\\r')

        return text

    def _log(self, event_type: str, session_id: str, data: Dict[str, Any]):
        """Internal method for formatting and storing log entries."""
        # Sanitize all string values in data dict
        sanitized_data = {}
        for key, value in data.items():
            if isinstance(value, str):
                sanitized_data[key] = self._sanitize_for_log(value)
            elif isinstance(value, (int, float, bool)):
                sanitized_data[key] = value
            else:
                sanitized_data[key] = self._sanitize_for_log(str(value))

        log_entry = {
            "timestamp_ms": int(time.time() * 1000),
            "type": event_type,
            "session_id": self._sanitize_for_log(session_id, 256),
            "data": sanitized_data
        }

        try:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(json.dumps(log_entry, ensure_ascii=False) + '\n')
        except IOError as e:
            print(f"[ERROR] Unable to write to log file: {e}")

    def log_connection(self, session_id: str, ip: str, port: int, protocol: str):
        """Log connection establishment."""
        self._log("CONNECTION_START", session_id, {
            "ip": ip,
            "port": port,
            "protocol": protocol
        })

    def log_command(self, session_id: str, command: str, output_len: int, latency_ms: int, status: str = "SUCCESS"):
        """Log executed command and its simulation."""
        log_data = {
            "command_input": command,
            "status": status,
            "output_length": output_len,
            "latency_ms": latency_ms
        }
        self._log("COMMAND_EXEC", session_id, log_data)

        self.last_commands.insert(0, {
            "time": time.strftime("%H:%M:%S"),
            "session": session_id.split('_')[0],
            "command": command.strip()[:50]
        })
        self.last_commands = self.last_commands[:self.max_commands]

    def log_state_change(self, session_id: str, path: str, action: str):
        """Log filesystem state change."""
        self._log("STATE_CHANGE", session_id, {
            "path": path,
            "action": action
        })

    def log_disconnect(self, session_id: str, reason: str = "Graceful"):
        """Log connection termination."""
        self._log("CONNECTION_END", session_id, {"reason": reason})
