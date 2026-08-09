import os
import tempfile


def _find_writable_dir(preferred: str) -> str:
    if os.path.isabs(preferred):
        base = preferred
    else:
        base = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), preferred
        )

    parent = os.path.dirname(base) or "."
    if os.access(parent, os.W_OK):
        return base

    return os.path.join(
        tempfile.gettempdir(), "handshakeCracker", preferred.lstrip("./\\")
    )


WORDLIST_URL = "https://raw.githubusercontent.com/Mysteriza/WiFi-Password-Wordlist/main/wifi-wordlist.txt"
AIRCRACK_WIN_URL = "https://download.aircrack-ng.org/aircrack-ng-1.7-win.zip"
HANDSHAKES_DIR = "handshakes"
RESULTS_DIR = _find_writable_dir("cracked_results")
WORDLIST_NAME = "wifi-wordlist.txt"
WORDLIST_ETAG_FILE = "wifi-wordlist.txt.etag"
BIN_DIR = _find_writable_dir("bin")

HASHCAT_VERSION = "7.1.2"
HASHCAT_URL = f"https://github.com/hashcat/hashcat/releases/download/v{HASHCAT_VERSION}/hashcat-{HASHCAT_VERSION}.7z"
HCOV_DIR = _find_writable_dir("hc22000_cache")

DEPS_DIR = "dependencies"
AIRCRACK_ZIP_NAME = "aircrack-ng-1.7-win.zip"
HASHCAT_ARCHIVE_NAME = f"hashcat-{HASHCAT_VERSION}.7z"

AIRCRACK_WIN_SHA256 = "767A456BF0675032D37D3C8CAF05E2E5DCB105C218614B2E4E42B51370D05205"
HASHCAT_SHA256 = "80DB0316387794CE9D14ED376DA75B8A7742972485B45DB790F5F8260307FF98"
