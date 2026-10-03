"""Shared cracked-password result writer."""

from __future__ import annotations

import os
import sys

from src.config import RESULTS_DIR
from src.utils import sanitize_ssid


def save_cracked_result(
    display_essid: str,
    wordlist_path: str,
    password: str,
    duration_str: str,
    handshake_path: str | None = None,
    avg_speed_str: str | None = None,
) -> str:
    os.makedirs(RESULTS_DIR, exist_ok=True)
    safe_essid = sanitize_ssid(display_essid)
    result_file = os.path.join(RESULTS_DIR, f"{safe_essid}_cracked_password.txt")
    with open(result_file, "w", encoding="utf-8") as f:
        f.write(f"Network (ESSID): {display_essid}\n")
        if handshake_path:
            f.write(f"Handshake File: {os.path.basename(handshake_path)}\n")
        f.write(f"Wordlist Used: {os.path.basename(wordlist_path)}\n")
        f.write(f"Password Found: {password}\n")
        f.write(f"Time Taken: {duration_str}\n")
        if avg_speed_str is not None:
            f.write("\n--- Cracking Statistics ---\n")
            f.write(f"Total Duration : {duration_str}\n")
            f.write(f"Avg Speed      : {avg_speed_str} passwords/s\n")
    if sys.platform != "win32":
        try:
            os.chmod(result_file, 0o600)
        except OSError:
            pass
    return result_file
