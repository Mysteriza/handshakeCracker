"""Interactive prompts (wordlist picker, manual handshake entry)."""

from __future__ import annotations

import os
import sys
import time

from prompt_toolkit.completion import PathCompleter
from prompt_toolkit.shortcuts import PromptSession
from prompt_toolkit.validation import ValidationError, Validator

from src.console import colored_log, console, log_error
from src.io import format_file_size


class PcapValidator(Validator):
    def validate(self, document):
        text = document.text
        if text.lower() in ("q", "done"):
            return
        if not os.path.exists(text):
            raise ValidationError(
                message=f"File not found: {text}", cursor_position=len(text)
            )
        if not text.lower().endswith((".cap", ".pcap", ".hc22000")):
            raise ValidationError(
                message=f"Not a .cap/.pcap/.hc22000 file: {text}",
                cursor_position=len(text),
            )


class WordlistValidator(Validator):
    def validate(self, document):
        text = document.text.strip().strip("\"'")
        if not text:
            raise ValidationError(message="Path cannot be empty.", cursor_position=0)
        if not os.path.isfile(text):
            raise ValidationError(
                message=f"File not found: {text}", cursor_position=len(text)
            )


def choose_wordlist(session: PromptSession, default_path: str) -> str:
    """Prompt user to pick a discovered wordlist or custom path. Returns chosen path."""
    console.print("\n[bold cyan]Wordlist Selection[/bold cyan]")

    root_dir = os.path.dirname(os.path.abspath(default_path))
    discovered_wordlists = []

    ignore_files = {"requirements.txt"}

    if os.path.exists(root_dir):
        with os.scandir(root_dir) as it:
            for entry in it:
                if not entry.is_file():
                    continue
                name = entry.name
                if not name.endswith((".txt", ".lst", ".dict")):
                    continue
                if name in ignore_files or name.startswith("debug_log"):
                    continue
                discovered_wordlists.append(entry.path)

    discovered_wordlists.sort()
    if default_path in discovered_wordlists:
        discovered_wordlists.remove(default_path)
        discovered_wordlists.insert(0, default_path)
    elif os.path.isfile(default_path):
        discovered_wordlists.insert(0, default_path)

    for i, path in enumerate(discovered_wordlists, 1):
        name = os.path.basename(path)
        try:
            size_str = format_file_size(os.path.getsize(path))
            console.print(f"  {i}. Use {name} ({size_str})")
        except OSError:
            console.print(f"  {i}. Use {name}")

    custom_idx = len(discovered_wordlists) + 1
    console.print(f"  {custom_idx}. Use custom wordlist file")

    valid_choices = {str(i) for i in range(1, custom_idx + 1)}
    while True:
        choice = input(f"  Choose [1-{custom_idx}] (default: 1): ").strip() or "1"
        if choice in valid_choices:
            break
        colored_log(
            "error", f"Invalid choice. Enter a number between 1 and {custom_idx}."
        )

    if choice == str(custom_idx):
        console.print(
            "  Example: C:\\Users\\You\\wordlist.txt  or  /home/user/wordlist.txt"
        )
        console.print("  Press TAB for auto-completion.")
        while True:
            try:
                raw_path = session.prompt(
                    "  Custom wordlist path: ",
                    completer=PathCompleter(only_directories=False, expanduser=True),
                    validator=WordlistValidator(),
                    validate_while_typing=True,
                ).strip()
                custom_path = raw_path.strip("\"'")
                break
            except ValidationError as e:
                colored_log("error", str(e))
            except (EOFError, KeyboardInterrupt):
                if discovered_wordlists:
                    fallback = discovered_wordlists[0]
                    colored_log(
                        "warning", f"Falling back to {os.path.basename(fallback)}."
                    )
                    return fallback
                colored_log("warning", "Falling back to default wordlist.")
                return default_path
        final_path = custom_path
    else:
        final_path = discovered_wordlists[int(choice) - 1]

    if os.path.exists(final_path):
        name = os.path.basename(final_path)
        try:
            size_str = format_file_size(os.path.getsize(final_path))
            colored_log(
                "success",
                f"Wordlist loaded: {name} | Path: {final_path} ({size_str})",
            )
        except OSError:
            colored_log("success", f"Wordlist loaded: {name} | Path: {final_path}")

    return final_path


def get_manual_handshake_paths(session: PromptSession) -> list[str]:
    manual_queue = []
    console.print("\nPlease enter handshake file paths (.cap/.pcap) one by one.")
    console.print(
        "(Type 'done' or 'q' to finish adding files. Use TAB for auto-completion.)"
    )

    while True:
        try:
            current_input_path = session.prompt(
                f"Handshake {len(manual_queue) + 1} Path: ",
                completer=PathCompleter(only_directories=False, expanduser=True),
                validator=PcapValidator(),
                validate_while_typing=True,
            ).strip()

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
                "An error occurred during file path input. Please try again or restart.",
            )
            time.sleep(1)

    return manual_queue
