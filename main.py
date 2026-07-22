#!/usr/bin/env python3
import os
import sys
import time

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from prompt_toolkit import prompt
    from prompt_toolkit.completion import PathCompleter
    from prompt_toolkit.validation import Validator, ValidationError
    from prompt_toolkit.shortcuts import PromptSession
    from prompt_toolkit.history import InMemoryHistory
    from scapy.all import rdpcap
    from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeResp, Dot11Elt
    from scapy.layers.eap import EAPOL, EAPOL_KEY
except ImportError:
    print("Required Python libraries not found. Attempting to install them...")
    import subprocess
    try:
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install",
             "rich", "prompt_toolkit", "scapy"]
        )
        print("Libraries installed successfully. Please restart the program.")
        sys.exit(0)
    except Exception as e:
        print(f"Failed to install required libraries: {e}")
        print("Please install them manually: pip install rich prompt_toolkit scapy")
        sys.exit(1)


from src.console import console, colored_log, log_error
from src.config import HANDSHAKES_DIR, WORDLIST_NAME
from src.utils import (
    sanitize_ssid,
    scan_default_directory,
)
from src.validator import validate_all_handshakes
from src.cracker import get_already_cracked_essids, crack_handshake
from src.setup import auto_setup
from src.gpu import has_discrete_gpu, get_gpu_name
from src.hashcat_cracker import hashcat_crack_handshake, ensure_hashcat
from src.updater import check_for_updates, show_version_info


class PcapValidator(Validator):
    def validate(self, document):
        text = document.text
        if text.lower() in ("q", "done"):
            return
        if not os.path.exists(text):
            raise ValidationError(
                message=f"File not found: {text}", cursor_position=len(text)
            )
        if not (text.lower().endswith(".cap") or text.lower().endswith(".pcap")):
            raise ValidationError(
                message=f"Not a .cap or .pcap file: {text}",
                cursor_position=len(text),
            )


def get_manual_handshake_paths(session: PromptSession) -> list[str]:
    manual_queue = []
    console.print("\nPlease enter handshake file paths (.cap/.pcap) one by one.")
    console.print(
        "(Type 'done' or 'q' to finish adding files. "
        "Use TAB for auto-completion.)"
    )

    while True:
        try:
            current_input_path = (
                session.prompt(
                    f"Handshake {len(manual_queue) + 1} Path: ",
                    completer=PathCompleter(only_directories=False, expanduser=True),
                    validator=PcapValidator(),
                    validate_while_typing=True,
                )
                .strip()
            )

            if current_input_path.lower() in ("done", "q"):
                break

            manual_queue.append(current_input_path)
            colored_log(
                "info",
                f"Added: {os.path.basename(current_input_path)} to queue.",
            )

        except ValidationError as e:
            colored_log("error", str(e))
        except EOFError:
            colored_log("info", "Exiting program.")
            sys.exit(0)
        except Exception as e:
            log_error("Error during manual handshake file input.", e)
            colored_log(
                "error",
                "An error occurred during file path input. "
                "Please try again or restart.",
            )
            time.sleep(1)

    return manual_queue


SEPARATOR = "-" * 60

def main():
    if check_for_updates():
        sys.exit(0)

    os.system("cls" if os.name == "nt" else "clear")

    try:
        if not auto_setup():
            sys.exit(1)

        wordlist_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), WORDLIST_NAME
        )
        if os.path.exists(wordlist_path):
            n = 0
            with open(wordlist_path, 'r', encoding='utf-8', errors='replace') as f:
                for _ in f:
                    n += 1
            colored_log("info", f"{n:,} passwords loaded.".replace(",", "."))
        show_version_info()

        use_hashcat = has_discrete_gpu()
        if use_hashcat:
            gpu_name = get_gpu_name()
            colored_log("info", f"Discrete GPU detected: {gpu_name or 'Unknown'}")
            colored_log("info", "Will use hashcat (GPU accelerated cracking).")
            if not ensure_hashcat():
                colored_log("warning", "hashcat setup failed — falling back to CPU (aircrack-ng).")
                use_hashcat = False
        else:
            colored_log("info", "No discrete GPU detected — using CPU (aircrack-ng).")

        session = PromptSession(history=InMemoryHistory())

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
            console.print(
                f"Found {len(found_files)} .cap/.pcap files "
                f"in '{HANDSHAKES_DIR}'."
            )

        if not handshake_queue:
            colored_log("warning", "No handshake files to process. Exiting.")
            sys.exit(0)

        valid_files, invalid_files = validate_all_handshakes(handshake_queue)

        if not valid_files:
            colored_log("warning", "No valid handshake files to process. Exiting.")
            sys.exit(0)

        handshake_queue = valid_files
        console.print(
            f"Processing {len(handshake_queue)} valid handshake(s)..."
        )

        already_cracked = get_already_cracked_essids()
        if already_cracked:
            console.print(
                f"Found {len(already_cracked)} previously cracked "
                f"network(s). These will be skipped."
            )

        handshake_queue.sort(key=lambda p: os.path.getsize(p), reverse=True)

        for i, handshake_path in enumerate(handshake_queue):
            console.print(f"\n{SEPARATOR}")
            console.print(
                f"Handshake {i+1}/{len(handshake_queue)}:"
                f" {os.path.basename(handshake_path)}"
            )

            base_essid = os.path.basename(handshake_path).replace(
                ".cap", ""
            ).replace(".pcap", "")
            safe_essid = sanitize_ssid(base_essid)

            if safe_essid in already_cracked:
                console.print(
                    f"  Network: {base_essid} already processed. Skipping."
                )
                continue

            if use_hashcat:
                cracked = hashcat_crack_handshake(
                    handshake_path, wordlist_path, base_essid
                )
                if cracked is None:
                    colored_log("warning", "Hashcat failed — falling back to aircrack-ng.")
                    cracked = crack_handshake(
                        handshake_path, wordlist_path, base_essid
                    )
            else:
                cracked = crack_handshake(
                    handshake_path, wordlist_path, base_essid
                )

            if cracked:
                console.print(f"  Done.")
                already_cracked.add(safe_essid)
            else:
                console.print(f"  Failed.")
                already_cracked.add(safe_essid)

        console.print(f"\n{SEPARATOR}")
        console.print("All handshakes have been processed!")
        console.print("Program finished. Exiting.\n")

    except KeyboardInterrupt:
        colored_log("warning", "Program interrupted by user (Ctrl+C). Exiting gracefully.")
        sys.exit(1)
    except Exception as e:
        log_error("A critical unhandled error occurred in main execution.", e)
        colored_log(
            "error",
            "A critical error occurred. Check 'error_log.txt' for details. Exiting.",
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
