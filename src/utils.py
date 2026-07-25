import os
import re
import sys
import tempfile
import urllib.request
import zipfile
import ctypes
import platform

from src.console import colored_log, log_error


def strip_capture_extension(path: str) -> str:
    base = os.path.basename(path)
    if base.lower().endswith('.cap'):
        return base[:-4]
    if base.lower().endswith('.pcap'):
        return base[:-5]
    return base

def lower_process_priority(pid: int):
    system = platform.system()
    if system == "Windows":
        try:
            # 0x1F0FFF = PROCESS_ALL_ACCESS, 0x00004000 = IDLE_PRIORITY_CLASS
            handle = ctypes.windll.kernel32.OpenProcess(0x1F0FFF, False, pid)
            ctypes.windll.kernel32.SetPriorityClass(handle, 0x00004000)
            ctypes.windll.kernel32.CloseHandle(handle)
        except Exception:
            pass
    else:
        try:
            os.setpriority(os.PRIO_PROCESS, pid, 19)
        except Exception:
            pass


def sanitize_ssid(ssid: str) -> str:
    return re.sub(r'[\\/*?:"<>|]', "", ssid).replace(" ", "_").strip()

def count_wordlist_lines(path: str) -> int:
    """Count lines in a wordlist file efficiently (1 MB buffer chunks)."""
    try:
        with open(path, 'rb') as f:
            return sum(chunk.count(b'\n') for chunk in iter(lambda: f.read(1024 * 1024), b''))
    except OSError:
        return 0


def scan_default_directory(directory_path: str) -> list[str]:
    found_files = []
    if not os.path.exists(directory_path):
        colored_log("error", f"Default directory {directory_path} not found.")
        return []

    colored_log("info", f"Scanning {directory_path}/ for .cap/.pcap files...")
    for root, _, files in os.walk(directory_path):
        for file in files:
            if file.lower().endswith((".cap", ".pcap")):
                full_path = os.path.join(root, file)
                found_files.append(full_path)
    return found_files



import hashlib

def download_with_progress(url: str, dest: str, label: str = "Downloading", expected_sha256: str | None = None) -> bool:
    try:
        def report(block_count, block_size, total_size):
            downloaded = block_count * block_size / (1024 * 1024)
            total = total_size / (1024 * 1024)
            sys.stdout.write(f"\r{label}: {downloaded:.1f}MB / {total:.1f}MB")
            sys.stdout.flush()

        urllib.request.urlretrieve(url, dest, report)
        sys.stdout.write("\n")

        if expected_sha256:
            sys.stdout.write(f"Verifying checksum for {label}...\n")
            hasher = hashlib.sha256()
            with open(dest, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hasher.update(chunk)
            actual_sha256 = hasher.hexdigest().upper()
            if actual_sha256 != expected_sha256.upper():
                colored_log("error", f"Checksum verification failed for {label}! Expected {expected_sha256}, got {actual_sha256}.")
                os.unlink(dest)
                return False
            colored_log("success", "Checksum verified successfully.")

        return True
    except KeyboardInterrupt:
        sys.stdout.write("\n")
        colored_log("warning", f"{label} interrupted by user.")
        return False
    except Exception as e:
        log_error(f"Failed to download {url}", e)
        return False


def extract_local_zip(zip_path: str, extract_to: str, subdir: str | None = None) -> bool:
    try:
        colored_log("info", f"Extracting {os.path.basename(zip_path)}...")
        os.makedirs(extract_to, exist_ok=True)

        with zipfile.ZipFile(zip_path, 'r') as zf:
            for member in zf.namelist():
                if subdir and not member.startswith(subdir):
                    continue
                rel_path = member[len(subdir):].lstrip('/') if subdir else member
                if not rel_path:
                    continue
                target = os.path.join(extract_to, rel_path)
                if member.endswith('/'):
                    os.makedirs(target, exist_ok=True)
                else:
                    os.makedirs(os.path.dirname(target), exist_ok=True)
                    with zf.open(member) as src, open(target, 'wb') as dst:
                        dst.write(src.read())

        colored_log("success", f"Extracted '{os.path.basename(zip_path)}'.")
        return True
    except KeyboardInterrupt:
        colored_log("warning", "Extraction interrupted by user.")
        return False
    except Exception as e:
        log_error(f"Failed to extract {zip_path}", e)
        return False


def download_wordlist(url: str, dest: str) -> bool:
    colored_log("info", "Wordlist not found. Downloading from GitHub...")
    result = download_with_progress(url, dest, "Downloading wordlist")
    if result:
        colored_log("success", f"Wordlist ready: {dest}")
        return True
    # Clean up partial on interrupt/failure
    if os.path.exists(dest):
        try:
            os.remove(dest)
        except OSError:
            pass
    colored_log("error", "Failed to download wordlist. Check your internet connection.")
    return False


def download_and_extract_zip(url: str, extract_to: str, subdir: str | None = None, expected_sha256: str | None = None) -> bool:
    tmp_path = None
    try:
        colored_log("info", "Downloading aircrack-ng for Windows...")
        colored_log("info", "The aircrack-ng server can be slow; this may take a few minutes.")
        with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as tmp:
            tmp_path = tmp.name

        if not download_with_progress(url, tmp_path, "Downloading aircrack-ng", expected_sha256):
            return False

        colored_log("info", "Extracting...")
        return extract_local_zip(tmp_path, extract_to, subdir)

    except Exception as e:
        log_error("Failed to download/extract aircrack-ng", e)
        colored_log("error", "Failed to set up aircrack-ng. Check your internet connection.")
        return False
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)
        elif tmp_path:
            pass


# ── Recovered UI Functions ──

import time
from prompt_toolkit.validation import Validator, ValidationError
from prompt_toolkit.shortcuts import PromptSession
from prompt_toolkit.completion import PathCompleter
from src.console import console

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


class WordlistValidator(Validator):
    def validate(self, document):
        text = document.text.strip().strip('"\'')
        if not text:
            raise ValidationError(message="Path cannot be empty.", cursor_position=0)
        if not os.path.isfile(text):
            raise ValidationError(
                message=f"File not found: {text}", cursor_position=len(text)
            )



def choose_wordlist(session: PromptSession, default_path: str) -> str:
    """Prompt user to pick default or custom wordlist. Returns chosen path."""
    console.print("\n[bold cyan]Wordlist Selection[/bold cyan]")
    console.print(f"  1. Use default wordlist ({os.path.basename(default_path)})")
    console.print("  2. Use custom wordlist file")

    while True:
        choice = input("  Choose [1/2] (default: 1): ").strip()
        if choice in ("", "1", "2"):
            break
        colored_log("error", "Invalid choice. Enter 1 for default or 2 for custom.")

    if choice == "2":
        console.print("  Example: C:\\Users\\You\\wordlist.txt  or  /home/user/wordlist.txt")
        console.print("  Press TAB for auto-completion.")
        while True:
            try:
                raw_path = session.prompt(
                    "  Custom wordlist path: ",
                    completer=PathCompleter(only_directories=False, expanduser=True),
                    validator=WordlistValidator(),
                    validate_while_typing=True,
                ).strip()
                custom_path = raw_path.strip('"\'')
                break
            except ValidationError as e:
                colored_log("error", str(e))
            except (EOFError, KeyboardInterrupt):
                colored_log("warning", "Falling back to default wordlist.")
                return default_path

        lines = count_wordlist_lines(custom_path)
        if lines:
            colored_log("info", f"Custom wordlist loaded: {lines:,} passwords.".replace(",", "."))

        return custom_path

    # Default: count lines if available
    lines = count_wordlist_lines(default_path)
    if lines:
        colored_log("info", f"{lines:,} passwords loaded.".replace(",", "."))

    return default_path



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

