import os
import re
import sys
import time
import math
import signal
import threading
import subprocess

from src.console import console, colored_log, log_error
from src.config import RESULTS_DIR
from src.utils import sanitize_ssid


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


def _terminate_all():
    for proc in _active_procs[:]:
        try:
            if proc.poll() is None:
                proc.kill()
        except Exception:
            pass
    _active_procs.clear()


def _write_status(spin_char: str, msg: str):
    sys.stdout.write(f"\r  {spin_char} {msg:<76}\r")
    sys.stdout.flush()


def _clear_status():
    sys.stdout.write("\r" + " " * 80 + "\r")
    sys.stdout.flush()


def _crack_worker(chunk_path: str, handshake_path: str, results: list, idx: int):
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
    _active_procs.append(proc)
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenProcess(0x1F0FFF, False, proc.pid)
        if handle:
            kernel32.SetPriorityClass(handle, 0x00004000)
            kernel32.CloseHandle(handle)
    except Exception:
        pass
    try:
        stdout, _ = proc.communicate()
        if "KEY FOUND!" in stdout:
            results.append(stdout)
    finally:
        if proc in _active_procs:
            _active_procs.remove(proc)


def crack_handshake(
    handshake_path: str, wordlist_path: str, display_essid: str
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

        if wl_size < 50_000_000:
            with open(wordlist_path, 'r', encoding='utf-8', errors='replace') as f:
                lines = f.readlines()
            total = len(lines)
            n = max(1, (os.cpu_count() or 2) // 2)
            chunk_size = math.ceil(total / n)

            threads = []
            for i in range(n):
                start = i * chunk_size
                end = min(start + chunk_size, total)
                if start >= total:
                    break
                chunk_path = f"{wordlist_path}.chunk.{i}"
                with open(chunk_path, 'w', encoding='utf-8') as cf:
                    cf.writelines(lines[start:end])
                chunk_paths.append(chunk_path)

            for i, cp in enumerate(chunk_paths):
                t = threading.Thread(
                    target=_crack_worker, args=(cp, handshake_path, found_results, i),
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
        else:
            try:
                proc = subprocess.Popen(
                    ["aircrack-ng", "-w", wordlist_path, handshake_path],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    text=True, encoding='utf-8', errors='replace',
                )
            except OSError as e:
                _clear_status()
                if getattr(e, 'winerror', None) == 225:
                    console.print("  Windows Defender blocked aircrack-ng.exe. Add an exclusion, then re-run.")
                else:
                    console.print(f"  Failed to launch aircrack-ng: {e}")
                return None
            _active_procs.append(proc)
            stdout, _ = proc.communicate()
            _active_procs.remove(proc)
            if "KEY FOUND!" in stdout:
                found_results.append(stdout)

        _clear_status()

        if not found_results:
            console.print(f"  Password not found in wordlist. Try a larger wordlist.")
            return None

        result_stdout = found_results[0]
        match = re.search(r"KEY FOUND!\s*\[\s*(.*?)\s*\]", result_stdout)
        if not match:
            console.print(f"  Password not found in wordlist. Try a larger wordlist.")
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
                os.path.basename(handshake_path)
                .replace(".cap", "").replace(".pcap", "")
                + "_determined_final"
            )

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

        console.print(f"  Saved to: {result_file}")
        return password

    except Exception as e:
        _terminate_all()
        _clear_status()
        log_error(f"Critical error during cracking process for {handshake_path}", e)
        console.print(f"  Cracking terminated due to an unexpected error.")
        return None
    finally:
        for cp in chunk_paths:
            try:
                os.remove(cp)
            except OSError:
                pass
        _terminate_all()
