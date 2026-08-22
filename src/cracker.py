import atexit
import math
import os
import re
import subprocess
import sys
import tempfile
import threading
import time

from src.backend import CrackerBackend
from src.config import RESULTS_DIR
from src.console import console, log_error
from src.utils import (lower_process_priority, sanitize_ssid,
                       strip_capture_extension)


def get_already_cracked_essids() -> set[str]:
    cracked_essids = set()
    if not os.path.exists(RESULTS_DIR):
        return cracked_essids

    try:
        for filename in os.listdir(RESULTS_DIR):
            if filename.endswith("_cracked_password.txt"):
                essid_part = filename.replace("_cracked_password.txt", "")
                cracked_essids.add(essid_part)
    except Exception as e:
        log_error(
            f"Error scanning results directory {RESULTS_DIR} for cracked ESSIDs.", e
        )

    return cracked_essids


_SPINNER = ["-", "\\", "|", "/"]
_active_procs: list[subprocess.Popen] = []
_active_procs_lock = threading.Lock()


def _terminate_all():
    with _active_procs_lock:
        for proc in _active_procs[:]:
            try:
                if proc.poll() is None:
                    proc.kill()
                    try:
                        proc.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        pass
            except Exception:
                pass
        _active_procs.clear()


def _cleanup_chunks():
    # No longer needed since chunking was removed
    pass


atexit.register(_terminate_all)
atexit.register(_cleanup_chunks)


def _write_status(spin_char: str, msg: str):
    sys.stdout.write(f"\r  {spin_char} {msg}".ljust(110) + "\r")
    sys.stdout.flush()


def _clear_status():
    sys.stdout.write("\r" + " " * 110 + "\r")
    sys.stdout.flush()


def _crack_worker(chunk_path: str, handshake_path: str, results: list):
    try:
        proc = subprocess.Popen(
            ["aircrack-ng", "-w", chunk_path, handshake_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except OSError as e:
        if getattr(e, "winerror", None) == 225:
            _clear_status()
            console.print(
                "  Windows Defender blocked aircrack-ng.exe. Add an exclusion in Windows Security, then re-run."
            )
        else:
            _clear_status()
            console.print(f"  Failed to launch aircrack-ng: {e}")
        return
    with _active_procs_lock:
        _active_procs.append(proc)

    lower_process_priority(proc.pid)

    try:
        stdout, _ = proc.communicate()
        if "KEY FOUND!" in stdout:
            results.append(stdout)
    finally:
        with _active_procs_lock:
            if proc in _active_procs:
                _active_procs.remove(proc)


class AircrackBackend(CrackerBackend):
    def crack(
        self, handshake_path: str, wordlist_path: str, display_essid: str
    ) -> str | None:
        try:
            messages = [
                f"Cracking {display_essid}... Initializing packet analyzer...",
                f"Cracking {display_essid}... Extracting handshake from capture...",
                f"Cracking {display_essid}... Loading wordlist into memory...",
                f"Cracking {display_essid}... Brute-forcing PMK computation...",
                f"Cracking {display_essid}... Testing key combinations...",
                f"Cracking {display_essid}... Almost there, checking matches...",
            ]
            msg_idx = 0
            spin_idx = 0
            iter_count = 0
            start_time = time.time()
            last_switch = start_time

            _write_status(_SPINNER[spin_idx % 4], messages[msg_idx])
            spin_idx += 1

            found_results = []

            # We pass the original wordlist_path directly to aircrack-ng.
            # Aircrack-ng streams the file natively without loading it entirely into RAM.
            t = threading.Thread(
                target=_crack_worker,
                args=(wordlist_path, handshake_path, found_results),
                daemon=True,
            )
            t.start()
            threads = [t]

            while len(found_results) == 0 and any(t.is_alive() for t in threads):
                iter_count += 1
                if iter_count % 6 == 0:
                    _write_status(_SPINNER[spin_idx % 4], messages[msg_idx])
                    spin_idx += 1
                now = time.time()
                if now - last_switch >= 6:
                    msg_idx = (msg_idx + 1) % len(messages)
                    last_switch = now
                time.sleep(0.1)

            _clear_status()

            # If we return early or finish, make sure to join threads
            for t in threads:
                if t.is_alive():
                    t.join(timeout=2)

            if not found_results:
                console.print(
                    "  Password not found in wordlist. Try a larger wordlist."
                )
                return None

            result_stdout = found_results[0]
            match = re.search(r"KEY FOUND!\s*\[\s*(.*?)\s*\]", result_stdout)
            if not match:
                console.print(
                    "  Password not found in wordlist. Try a larger wordlist."
                )
                return None

            password = match.group(1)
            elapsed = time.time() - start_time
            m, s = divmod(int(elapsed), 60)
            time_str = f"{m:02d}:{s:02d}"

            essid_match = re.search(r"SSID:\s*(.*)", result_stdout)
            final_essid = display_essid
            if essid_match and essid_match.group(1).strip() not in ("", "<hidden>"):
                final_essid = essid_match.group(1).strip()
            elif final_essid in ("<hidden>",) or final_essid.endswith("_from_filename"):
                final_essid = (
                    strip_capture_extension(handshake_path) + "_determined_final"
                )

            _clear_status()
            console.print(f"  Password: {password}")
            console.print(f"  Time: {time_str}")

            os.makedirs(RESULTS_DIR, exist_ok=True)
            safe_essid = sanitize_ssid(final_essid)
            result_file = os.path.join(
                RESULTS_DIR, f"{safe_essid}_cracked_password.txt"
            )
            with open(result_file, "w") as f:
                f.write(f"Network (ESSID): {final_essid}\n")
                f.write(f"Handshake File: {os.path.basename(handshake_path)}\n")
                f.write(f"Wordlist Used: {os.path.basename(wordlist_path)}\n")
                f.write(f"Password Found: {password}\n")
                f.write(f"Time Taken: {time_str}\n")

            if sys.platform != "win32":
                try:
                    os.chmod(result_file, 0o600)
                except OSError:
                    pass

            console.print(f"  Saved to: {result_file}")
            return password

        except Exception as e:
            log_error(f"Critical error during cracking process for {handshake_path}", e)
            console.print("  Cracking terminated due to an unexpected error.")
            return None
        finally:
            _terminate_all()
            _clear_status()
