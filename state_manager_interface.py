# state_manager_interface.py

from abc import ABC, abstractmethod
from typing import Dict, Any, List

class IStateManager(ABC):
    """
    Abstrakte Schnittstelle für das Angreifer-Zustandsmanagement.
    Dieses Interface wird später von Agent_DatenbankUndLogger implementiert.
    """
    
    @abstractmethod
    async def create_session(self, ip_address: str, fingerprint: str = None) -> str:
        """Erstellt eine neue Angreifer-Sitzung und gibt die Sitzungs-ID zurück."""
        pass

    @abstractmethod
    async def get_session_info(self, session_id: str) -> Dict[str, Any]:
        """Gibt Metadaten zur Sitzung zurück (z.B. IP, Startzeit)."""
        pass

    @abstractmethod
    async def track_file_change(self, session_id: str, path: str, action: str, new_content: str = None) -> bool:
        """
        Speichert eine Zustandsänderung für das virtuelle Dateisystem des Angreifers.
        Action kann 'create', 'delete', 'modify' sein.
        """
        pass

    @abstractmethod
    async def get_file_changes(self, session_id: str) -> List[Dict[str, Any]]:
        """Gibt alle dynamischen Dateisystem-Änderungen für die Sitzung zurück."""
        pass
    
    @abstractmethod
    async def resolve_file_state(self, session_id: str, path: str) -> Dict[str, Any]:
        """
        Löst den aktuellen, effektiven Zustand einer Datei auf (statische Konfig + dynamische Änderungen).
        Wird später im Agent_DatenbankUndLogger implementiert.
        """
        pass

    @abstractmethod
    async def close_session(self, session_id: str) -> bool:
        """Markiert die Sitzung als beendet."""
        pass