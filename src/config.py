import os
import platform
import tempfile


def _find_writable_dir(preferred: str) -> str:
    if os.path.isabs(preferred):
        base = preferred
    else:
        base = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), preferred)
    try:
        os.makedirs(base, exist_ok=True)
        return base
    except (OSError, PermissionError):
        alt = os.path.join(tempfile.gettempdir(), "handshakeCracker", preferred.lstrip("./\\"))
        os.makedirs(alt, exist_ok=True)
        return alt


WORDLIST_URL = "https://raw.githubusercontent.com/Mysteriza/WiFi-Password-Wordlist/main/wifite.txt"
AIRCRACK_WIN_URL = "https://download.aircrack-ng.org/aircrack-ng-1.7-win.zip"
HANDSHAKES_DIR = "handshakes"
RESULTS_DIR = _find_writable_dir("cracked_results")
WORDLIST_NAME = "wifite.txt"
BIN_DIR = _find_writable_dir("bin")

HASHCAT_VERSION = "7.1.2"
HASHCAT_URL = f"https://github.com/hashcat/hashcat/releases/download/v{HASHCAT_VERSION}/hashcat-{HASHCAT_VERSION}.7z"
HASHCAT_DIR = os.path.join(BIN_DIR, f"hashcat-{HASHCAT_VERSION}")
HASHCAT_EXE = "hashcat.exe" if platform.system() == "Windows" else "hashcat"
HCOV_DIR = _find_writable_dir("hc22000_cache")

DEPS_DIR = "dependencies"
AIRCRACK_ZIP_NAME = "aircrack-ng-1.7-win.zip"
HASHCAT_ARCHIVE_NAME = f"hashcat-{HASHCAT_VERSION}.7z"
