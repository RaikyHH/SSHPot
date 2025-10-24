# state_manager.py

import sqlite3
import time
import json
from typing import Dict, Any, List
from state_manager_interface import IStateManager
from config_engine import ConfigEngine

class StateManager(IStateManager):
    """
    SQLite-based state manager implementation.
    Stores session information and dynamic filesystem changes per attacker.
    """

    def __init__(self, db_path: str = ':memory:'):
        """Initializes database connection and creates necessary tables."""
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.cursor = self.conn.cursor()
        self._create_tables()
        self.config = ConfigEngine()  # Access to static files

    def _create_tables(self):
        """Creates tables for sessions and state changes."""
        # Table for attacker sessions
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                ip_address TEXT NOT NULL,
                fingerprint TEXT,
                start_time REAL NOT NULL,
                end_time REAL,
                status TEXT NOT NULL -- active, closed
            )
        """)
        # Table for dynamic filesystem changes
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS file_changes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                path TEXT NOT NULL,
                action TEXT NOT NULL, -- create, delete, modify
                content TEXT,
                timestamp REAL NOT NULL,
                FOREIGN KEY(session_id) REFERENCES sessions(id)
            )
        """)
        self.conn.commit()

    async def create_session(self, ip_address: str, fingerprint: str = None) -> str:
        """Creates a new attacker session."""
        session_id = f"{ip_address}_{int(time.time() * 1000)}"
        start_time = time.time()
        self.cursor.execute(
            "INSERT INTO sessions VALUES (?, ?, ?, ?, NULL, 'active')",
            (session_id, ip_address, fingerprint, start_time)
        )
        self.conn.commit()
        return session_id

    async def get_session_info(self, session_id: str) -> Dict[str, Any]:
        """Gibt Metadaten zur Sitzung zurück."""
        self.cursor.execute("SELECT * FROM sessions WHERE id=?", (session_id,))
        row = self.cursor.fetchone()
        if row:
            # Beispielhaftes Mapping der Spalten
            keys = ['id', 'ip_address', 'fingerprint', 'start_time', 'end_time', 'status']
            return dict(zip(keys, row))
        return {}

    async def track_file_change(self, session_id: str, path: str, action: str, new_content: str = None) -> bool:
        """Speichert eine Zustandsänderung."""
        # DoS Protection: Limit number of file changes per session
        MAX_FILE_CHANGES_PER_SESSION = 10000

        # Check current count
        self.cursor.execute(
            "SELECT COUNT(*) FROM file_changes WHERE session_id=?",
            (session_id,)
        )
        count = self.cursor.fetchone()[0]

        if count >= MAX_FILE_CHANGES_PER_SESSION:
            print(f"[SECURITY] Session {session_id} exceeded max file changes limit ({MAX_FILE_CHANGES_PER_SESSION})")
            return False

        # Limit content size to prevent storage exhaustion
        if new_content and len(new_content) > 1048576:  # 1MB limit
            new_content = new_content[:1048576] + "...[TRUNCATED]"

        timestamp = time.time()
        try:
            self.cursor.execute(
                "INSERT INTO file_changes (session_id, path, action, content, timestamp) VALUES (?, ?, ?, ?, ?)",
                (session_id, path, action, new_content, timestamp)
            )
            self.conn.commit()
            return True
        except sqlite3.Error as e:
            print(f"Error saving state change: {e}")
            return False

    async def get_file_changes(self, session_id: str) -> List[Dict[str, Any]]:
        """Gibt alle dynamischen Dateisystem-Änderungen für die Sitzung zurück."""
        self.cursor.execute(
            "SELECT path, action, content, timestamp FROM file_changes WHERE session_id=? ORDER BY timestamp ASC", 
            (session_id,)
        )
        changes = []
        for row in self.cursor.fetchall():
            changes.append({'path': row[0], 'action': row[1], 'content': row[2], 'timestamp': row[3]})
        return changes

    async def resolve_file_state(self, session_id: str, path: str) -> Dict[str, Any]:
        """Löst den aktuellen, effektiven Zustand einer Datei auf."""
        
        # 1. Statischer Zustand aus der Konfiguration
        static_info = self.config.get_file_info(path)
        
        # 2. Dynamische Änderungen des Angreifers
        self.cursor.execute(
            "SELECT action, content FROM file_changes WHERE session_id=? AND path=? ORDER BY timestamp DESC LIMIT 1",
            (session_id, path)
        )
        latest_change = self.cursor.fetchone()
        
        if latest_change:
            action = latest_change[0]
            content = latest_change[1]
            
            if action == 'delete':
                return {'exists': False}
            
            # Bei 'create' oder 'modify' überschreibt der dynamische Zustand den statischen
            resolved_state = static_info.copy()
            resolved_state['exists'] = True
            
            # Annahme: 'create' und 'modify' aktualisieren 'content'
            if content is not None:
                resolved_state['content'] = content
            
            # Bei 'create' bekommt die Datei/das Verzeichnis Default-Metadaten, falls nicht statisch definiert
            if action == 'create' and not static_info:
                resolved_state.update({
                    'type': 'file' if not path.endswith('/') else 'dir',
                    'perms': 'rw-r--r--',
                    'content': content if content is not None else '',
                })
            
            return resolved_state
        
        # 3. Kein dynamischer Zustand -> Nur statischer Zustand
        if static_info:
            static_info['exists'] = True
            return static_info
        
        return {'exists': False}

    async def close_session(self, session_id: str) -> bool:
        """Markiert die Sitzung als beendet."""
        end_time = time.time()
        self.cursor.execute(
            "UPDATE sessions SET end_time=?, status='closed' WHERE id=?",
            (end_time, session_id)
        )
        self.conn.commit()
        return self.cursor.rowcount > 0

    def get_active_sessions_count(self) -> int:
        """Gibt die Anzahl der aktiven Sitzungen zurück."""
        self.cursor.execute("SELECT COUNT(*) FROM sessions WHERE status='active'")
        return self.cursor.fetchone()[0]