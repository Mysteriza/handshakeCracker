"""Small pure helpers + backwards-compatible re-exports.

Heavy I/O lives in src.io, prompts in src.ui. This module stays so existing
`from src.utils import ...` imports keep working.
"""

from __future__ import annotations

import ctypes
import os
import platform
import re

from src.console import colored_log, log_error
from src.io import (
    download_and_extract_zip,
    download_with_progress,
    download_wordlist,
    extract_local_zip,
    format_file_size,
)
from src.ui import (
    PcapValidator,
    WordlistValidator,
    choose_wordlist,
    get_manual_handshake_paths,
)

__all__ = [
    "strip_capture_extension",
    "lower_process_priority",
    "format_file_size",
    "sanitize_ssid",
    "scan_default_directory",
    "find_exe_in_path",
    "download_with_progress",
    "extract_local_zip",
    "download_wordlist",
    "download_and_extract_zip",
    "PcapValidator",
    "WordlistValidator",
    "choose_wordlist",
    "get_manual_handshake_paths",
]


def strip_capture_extension(path: str) -> str:
    base = os.path.basename(path)
    lower = base.lower()
    if lower.endswith(".cap"):
        return base[:-4]
    if lower.endswith(".pcap"):
        return base[:-5]
    if lower.endswith(".hc22000"):
        return base[:-8]
    return base


def lower_process_priority(pid: int):
    system = platform.system()
    if system == "Windows":
        try:
            handle = ctypes.windll.kernel32.OpenProcess(0x1F0FFF, False, pid)
            if handle:
                ctypes.windll.kernel32.SetPriorityClass(handle, 0x00004000)
                ctypes.windll.kernel32.CloseHandle(handle)
        except Exception:
            pass
    else:
        try:
            os.setpriority(os.PRIO_PROCESS, pid, 19)
        except Exception:
            pass


_SSID_ILLEGAL = re.compile(r'[\\/*?:"<>|]')


def sanitize_ssid(ssid: str) -> str:
    return _SSID_ILLEGAL.sub("", ssid).strip().replace(" ", "_")


def scan_default_directory(directory_path: str) -> list[str]:
    found_files = []

    if not os.path.exists(directory_path):
        colored_log("error", f"Default directory {directory_path} not found.")
        return []

    colored_log("info", f"Scanning {directory_path}/ for .cap/.pcap/.hc22000 files...")
    try:
        with os.scandir(directory_path) as it:
            for entry in it:
                if entry.is_file() and entry.name.lower().endswith(
                    (".cap", ".pcap", ".hc22000")
                ):
                    found_files.append(entry.path)
    except OSError as e:
        log_error(f"Failed to scan {directory_path}", e)
    return found_files


def find_exe_in_path(exe: str) -> str | None:
    for path in os.environ.get("PATH", "").split(os.pathsep):
        candidate = os.path.join(path.strip('"'), exe)
        if os.path.isfile(candidate):
            return candidate
    return None
