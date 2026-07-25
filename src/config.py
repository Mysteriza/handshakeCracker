import os
import platform
import tempfile


def _find_writable_dir(preferred: str) -> str:
    if os.path.isabs(preferred):
        base = preferred
    else:
        base = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), preferred)
    
    parent = os.path.dirname(base) or '.'
    if os.access(parent, os.W_OK):
        return base

    return os.path.join(tempfile.gettempdir(), "handshakeCracker", preferred.lstrip("./\\"))


WORDLIST_URL = "https://raw.githubusercontent.com/Mysteriza/WiFi-Password-Wordlist/main/wifite.txt"
AIRCRACK_WIN_URL = "https://download.aircrack-ng.org/aircrack-ng-1.7-win.zip"
HANDSHAKES_DIR = "handshakes"
RESULTS_DIR = _find_writable_dir("cracked_results")
WORDLIST_NAME = "wifite.txt"
BIN_DIR = _find_writable_dir("bin")

HASHCAT_VERSION = "6.2.6"
HASHCAT_URL = f"https://github.com/hashcat/hashcat/releases/download/v{HASHCAT_VERSION}/hashcat-{HASHCAT_VERSION}.7z"
HASHCAT_DIR = os.path.join(BIN_DIR, f"hashcat-{HASHCAT_VERSION}")
HASHCAT_EXE = "hashcat.exe" if platform.system() == "Windows" else "hashcat"
HCOV_DIR = _find_writable_dir("hc22000_cache")

DEPS_DIR = "dependencies"
AIRCRACK_ZIP_NAME = "aircrack-ng-1.7-win.zip"
HASHCAT_ARCHIVE_NAME = f"hashcat-{HASHCAT_VERSION}.7z"

AIRCRACK_WIN_SHA256 = "767A456BF0675032D37D3C8CAF05E2E5DCB105C218614B2E4E42B51370D05205"
HASHCAT_SHA256 = "96697E9EF6A795D45863C91D61BE85A9F138596E3151E7C2CD63CCF48AAA8783"
