#!/usr/bin/env python3
"""Wi-Fi Handshake Cracker — fully automated setup & cracking."""

# ruff: noqa: E402
import os
import signal
import subprocess
import sys

# ── Phase 0: Auto-Update Check ─────────────────────────────────────────
try:
    from src.updater import check_and_update

    check_and_update()
except Exception:
    pass

# ── Phase 1: Auto-install Python dependencies ──────────────────────────
_REQUIREMENTS = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "requirements.txt"
)

from src.bootstrap import pip_install_requirements as _pip_install_requirements

try:
    import prompt_toolkit  # noqa: F401
    import rich  # noqa: F401
    import scapy  # noqa: F401
except ImportError:
    print("Required Python libraries not found. Installing...")
    if _pip_install_requirements(_REQUIREMENTS):
        print("Libraries installed successfully. Please restart the program.")
        sys.exit(0)
    else:
        print("Failed to install required libraries.")
        print(f"Try manually: pip install --user -r {_REQUIREMENTS}")
        print(
            f"Or with override: pip install --break-system-packages -r {_REQUIREMENTS}"
        )
        sys.exit(1)

# ── Phase 2: Project imports ───────────────────────────────────────────

from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.shortcuts import PromptSession

from src.backend import CrackerBackend
from src.config import HANDSHAKES_DIR, WORDLIST_NAME
from src.console import colored_log, console, log_debug, log_error
from src.cracker import AircrackBackend, get_already_cracked_essids
from src.hashcat import HASHCAT_EXHAUSTED, HashcatBackend
from src.setup import auto_setup
from src.utils import (choose_wordlist, get_manual_handshake_paths,
                       sanitize_ssid, scan_default_directory,
                       strip_capture_extension)
from src.validator import validate_all_handshakes

SEPARATOR = "-" * 60


def main():
    try:
        signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    except AttributeError:
        pass

    # Clear screen securely using ANSI escape codes
    print("\033[H\033[J", end="", flush=True)

    try:
        setup = auto_setup()
        if not setup.get("aircrack_available") and not setup.get("hashcat_available"):
            sys.exit(1)

        use_hashcat = setup.get("hashcat_available", False)
        gpu_name = setup.get("gpu_name")

        if use_hashcat and gpu_name:
            gpu_type = "Discrete" if setup.get("gpu_is_discrete") else "Integrated"
            colored_log(
                "info", f"GPU detected: {gpu_name} ({gpu_type}) — using hashcat (GPU)."
            )
        elif use_hashcat:
            colored_log("info", "Using hashcat (GPU/OpenCL).")
        else:
            colored_log("info", "Using aircrack-ng (CPU).")

        log_debug(
            f"main: hashcat={'yes' if use_hashcat else 'no'}, "
            f"gpu_name={gpu_name}, "
            f"aircrack-ng={'yes' if setup.get('aircrack_available') else 'no'}"
        )

        session = PromptSession(history=InMemoryHistory())

        # ── Wordlist selection ─────────────────────────────────────────
        default_wordlist = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), WORDLIST_NAME
        )
        wordlist_path = choose_wordlist(session, default_wordlist)

        found_files = scan_default_directory(HANDSHAKES_DIR)
        handshake_queue = []

        if not found_files:
            console.print(f"No .cap/.pcap files found in '{HANDSHAKES_DIR}'.")
            switch_to_manual = (
                input("Switch to manual file entry? (y/N): ").strip().lower()
            )
            if switch_to_manual == "y":
                handshake_queue = get_manual_handshake_paths(session)
            else:
                console.print("Exiting.")
                sys.exit(0)
        else:
            handshake_queue.extend(found_files)
            colored_log(
                "info",
                f"Found {len(found_files)} .cap/.pcap file(s) in '{HANDSHAKES_DIR}'.",
            )

        if not handshake_queue:
            colored_log("warning", "No handshake files to process. Exiting.")
            sys.exit(0)

        valid_files_map, _ = validate_all_handshakes(handshake_queue)

        if not valid_files_map:
            colored_log("warning", "No valid handshake files to process. Exiting.")
            sys.exit(0)

        handshake_queue = list(valid_files_map.keys())
        console.print(f"Processing {len(handshake_queue)} valid handshake(s)...")

        already_cracked = get_already_cracked_essids()
        handshake_queue.sort(key=lambda p: os.path.getsize(p), reverse=True)

        seen = set()
        deduped = []
        skipped_count = 0

        for p in handshake_queue:
            safe = sanitize_ssid(strip_capture_extension(p))
            if safe in already_cracked or safe in seen:
                skipped_count += 1
            else:
                seen.add(safe)
                deduped.append(p)

        if skipped_count:
            console.print(
                f"Skipped {skipped_count} previously cracked or duplicate "
                f"network(s). Processing {len(deduped)} remaining."
            )

        backend: CrackerBackend
        if use_hashcat:
            packets_map = {f: v.relevant_packets for f, v in valid_files_map.items()}
            backend = HashcatBackend(setup.get("gpu_is_discrete", False), packets_map)
        else:
            backend = AircrackBackend()

        for idx, handshake_path in enumerate(deduped, 1):
            base_essid = strip_capture_extension(handshake_path)

            console.print(f"\n{SEPARATOR}")
            console.print(f"Handshake {idx}/{len(deduped)}: {base_essid}")

            log_debug(f"main: routing to {backend.__class__.__name__} for {base_essid}")
            cracked = backend.crack(handshake_path, wordlist_path, base_essid)
            log_debug(f"main: backend returned {cracked!r}")

            if cracked is None and use_hashcat:
                colored_log("warning", "Hashcat failed — falling back to aircrack-ng.")
                log_debug("main: hashcat failed, fallback to AircrackBackend")
                fallback = AircrackBackend()
                cracked = fallback.crack(handshake_path, wordlist_path, base_essid)
                log_debug(f"main: fallback aircrack-ng returned {cracked!r}")
            elif cracked == HASHCAT_EXHAUSTED:
                cracked = None
                colored_log(
                    "warning", "Password not found in wordlist. Try a larger wordlist."
                )

            if cracked:
                console.print("  [green]Done.[/green]")
            else:
                console.print("  [red]Failed.[/red]")

        console.print(f"\n{SEPARATOR}")
        console.print("All handshakes have been processed!")
        console.print("Program finished. Exiting.\n")

    except KeyboardInterrupt:
        colored_log(
            "warning", "Program interrupted by user (Ctrl+C). Exiting gracefully."
        )
        sys.exit(1)
    except Exception as e:
        log_error("A critical unhandled error occurred in main execution.", e)
        colored_log(
            "error",
            "A critical error occurred. Check 'debug_log.txt' for details. Exiting.",
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
