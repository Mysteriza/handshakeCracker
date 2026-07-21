import os
import platform

WORDLIST_URL = "https://raw.githubusercontent.com/Mysteriza/WiFi-Password-Wordlist/main/wifite.txt"
AIRCRACK_WIN_URL = "https://download.aircrack-ng.org/aircrack-ng-1.7-win.zip"
HANDSHAKES_DIR = "handshakes"
RESULTS_DIR = "cracked_results"
WORDLIST_NAME = "wifite.txt"
BIN_DIR = "bin"

HASHCAT_VERSION = "6.2.6"
HASHCAT_WIN_URL = f"https://hashcat.net/files/hashcat-{HASHCAT_VERSION}.7z"
HASHCAT_LINUX_URL = f"https://hashcat.net/files/hashcat-{HASHCAT_VERSION}.tar.xz"
HASHCAT_DIR = os.path.join(BIN_DIR, f"hashcat-{HASHCAT_VERSION}")
HASHCAT_EXE = "hashcat.exe" if platform.system() == "Windows" else "hashcat"
HCOV_DIR = "hc22000_cache"
