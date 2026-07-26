import os
import re
import sys
import time
import math
import atexit
import tempfile
import threading
import subprocess

from src.console import console, log_error
from src.config import RESULTS_DIR
from src.utils import sanitize_ssid, strip_capture_extension, lower_process_priority
from src.backend import CrackerBackend


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
        log_error(f"Error scanning results directory {RESULTS_DIR} for cracked ESSIDs.", e)

    return cracked_essids


_SPINNER = ['-', '\\', '|', '/']
_active_procs: list[subprocess.Popen] = []
_active_procs_lock = threading.Lock()
_cached_chunks: dict[str, list[str]] = {}


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
    for paths in _cached_chunks.values():
        if not paths:
            continue
        chunk_dir = os.path.dirname(paths[0])
        for p in paths:
            try:
                os.remove(p)
            except OSError:
                pass
        try:
            os.rmdir(chunk_dir)
        except OSError:
            pass
    _cached_chunks.clear()


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
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding='utf-8', errors='replace',
        )
    except OSError as e:
        if getattr(e, 'winerror', None) == 225:
            _clear_status()
            console.print("  Windows Defender blocked aircrack-ng.exe. Add an exclusion in Windows Security, then re-run.")
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
        chunk_paths: list[str] = []
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

            wl_size = os.path.getsize(wordlist_path)
            found_results = []

            if wordlist_path not in _cached_chunks:
                n = max(1, (os.cpu_count() or 2) // 2)
                chunk_dir = tempfile.mkdtemp(prefix="hs_crack_")
                paths = []

                chunk_size_bytes = math.ceil(wl_size / n)

                with open(wordlist_path, 'rb') as f:
                    for i in range(n):
                        cp = os.path.join(chunk_dir, f"chunk_{i}.txt")
                        with open(cp, 'wb') as cf:
                            bytes_read = 0
                            while bytes_read < chunk_size_bytes:
                                chunk = f.read(min(1024 * 1024, chunk_size_bytes - bytes_read))
                                if not chunk:
                                    break
                                bytes_read += len(chunk)
                                cf.write(chunk)

                            # Read until the next newline so we don't break passwords
                            if bytes_read > 0 and chunk and not chunk.endswith(b'\n'):
                                remainder = f.readline()
                                cf.write(remainder)
                        paths.append(cp)
                _cached_chunks[wordlist_path] = paths

            chunk_paths = _cached_chunks[wordlist_path]
            threads = []

            for i, cp in enumerate(chunk_paths):
                t = threading.Thread(
                    target=_crack_worker, args=(cp, handshake_path, found_results),
                    daemon=True,
                )
                t.start()
                threads.append(t)

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
                console.print("  Password not found in wordlist. Try a larger wordlist.")
                return None

            result_stdout = found_results[0]
            match = re.search(r"KEY FOUND!\s*\[\s*(.*?)\s*\]", result_stdout)
            if not match:
                console.print("  Password not found in wordlist. Try a larger wordlist.")
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
                    strip_capture_extension(handshake_path)
                    + "_determined_final"
                )

            _clear_status()
            console.print(f"  Password: {password}")
            console.print(f"  Time: {time_str}")

            os.makedirs(RESULTS_DIR, exist_ok=True)
            safe_essid = sanitize_ssid(final_essid)
            result_file = os.path.join(RESULTS_DIR, f"{safe_essid}_cracked_password.txt")
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
