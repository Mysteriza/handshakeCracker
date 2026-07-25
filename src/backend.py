from typing import Protocol, Optional

class CrackerBackend(Protocol):
    def crack(self, handshake_path: str, wordlist_path: str, display_essid: str) -> Optional[str]:
        ...
