#!/usr/bin/env python3
"""Wi-Fi Handshake Cracker — fully automated setup & cracking."""
import os
import sys
import time
import subprocess

# ── Phase 1: Auto-install Python dependencies ──────────────────────────
_REQUIREMENTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "requirements.txt")


def _pip_install_requirements(req_path: str) -> bool:
    """Install pip packages with PEP 668 fallback."""
    base_cmd = [sys.executable, "-m", "pip", "install", "--user", "-r", req_path]
    try:
        subprocess.check_call(base_cmd)
        return True
    except subprocess.CalledProcessError as e:
        stderr = (e.stderr or "").lower() if e.stderr else ""
        stdout = (e.stdout or "").lower() if e.stdout else ""
        # PEP 668: externally-managed-environment
        if "externally-managed" in stderr or "externally-managed" in stdout:
            print("Detected PEP 668 (externally-managed environment). Retrying with --break-system-packages...")
            try:
                subprocess.check_call(base_cmd + ["--break-system-packages"])
                return True
            except subprocess.CalledProcessError:
                return False
        return False
    except Exception:
        return False


try:
    import rich  # noqa: F401
    import prompt_toolkit  # noqa: F401
    import scapy  # noqa: F401
except ImportError:
    print("Required Python libraries not found. Installing...")
    if _pip_install_requirements(_REQUIREMENTS):
        print("Libraries installed successfully. Please restart the program.")
        sys.exit(0)
    else:
        print(f"Failed to install required libraries.")
        print(f"Try manually: pip install --user -r {_REQUIREMENTS}")
        print(f"Or with override: pip install --break-system-packages -r {_REQUIREMENTS}")
        sys.exit(1)

# ── Phase 2: Project imports ───────────────────────────────────────────
from rich.console import Console
from prompt_toolkit.completion import PathCompleter
from prompt_toolkit.validation import Validator, ValidationError
from prompt_toolkit.shortcuts import PromptSession
from prompt_toolkit.history import InMemoryHistory

from src.console import console, colored_log, log_error, log_debug
from src.config import HANDSHAKES_DIR, WORDLIST_NAME
from src.utils import sanitize_ssid, scan_default_directory
from src.validator import validate_all_handshakes
from src.cracker import get_already_cracked_essids, crack_handshake
from src.hashcat_cracker import hashcat_crack_handshake
from src.setup import auto_setup




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
    os.system("cls" if os.name == "nt" else "clear")

    try:
        setup = auto_setup()
        if not setup.get("aircrack_available") and not setup.get("hashcat_available"):
            sys.exit(1)

        use_hashcat = setup.get("hashcat_available", False)
        log_debug(f"main: hashcat={'yes' if use_hashcat else 'no'}, aircrack-ng={'yes' if setup.get('aircrack_available') else 'no'}")

        wordlist_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), WORDLIST_NAME
        )
        wordlist_lines = 0
        if os.path.exists(wordlist_path):
            with open(wordlist_path, 'rb') as f:
                wordlist_lines = sum(chunk.count(b'\n') for chunk in iter(lambda: f.read(1024 * 1024), b''))
            colored_log("info", f"{wordlist_lines:,} passwords loaded.".replace(",", "."))

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
        handshake_queue = [
            p for p in handshake_queue
            if sanitize_ssid(os.path.basename(p).replace(
                ".cap", "").replace(".pcap", "")) not in already_cracked
        ]

        handshake_queue.sort(key=lambda p: os.path.getsize(p), reverse=True)

        seen = set(already_cracked)
        deduped = []
        for p in handshake_queue:
            safe = sanitize_ssid(os.path.basename(p).replace(
                ".cap", "").replace(".pcap", ""))
            if safe not in seen:
                seen.add(safe)
                deduped.append(p)

        skipped_count = len(handshake_queue) - len(deduped)
        if skipped_count:
            console.print(
                f"Skipped {skipped_count} previously cracked "
                f"network(s). Processing {len(deduped)} remaining."
            )

        for idx, handshake_path in enumerate(deduped, 1):
            base_essid = os.path.basename(handshake_path).replace(
                ".cap", ""
            ).replace(".pcap", "")

            console.print(f"\n{SEPARATOR}")
            console.print(f"Handshake {idx}/{len(deduped)}: {base_essid}")

            if use_hashcat:
                log_debug(f"main: routing to hashcat for {base_essid}")
                cracked = hashcat_crack_handshake(
                    handshake_path, wordlist_path, base_essid
                )
                log_debug(f"main: hashcat returned {cracked!r}")

                if cracked is None:
                    colored_log("warning", "Hashcat failed — falling back to aircrack-ng.")
                    log_debug(f"main: falling back to aircrack-ng for {base_essid}")
                    cracked = crack_handshake(
                        handshake_path, wordlist_path, base_essid
                    )
                    log_debug(f"main: aircrack-ng returned {cracked!r}")
            else:
                log_debug(f"main: routing to aircrack-ng for {base_essid}")
                cracked = crack_handshake(
                    handshake_path, wordlist_path, base_essid
                )
                log_debug(f"main: aircrack-ng returned {cracked!r}")

            if cracked:
                console.print(f"  Done.")
            else:
                console.print(f"  Failed.")

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
