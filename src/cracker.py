import os
import re
import time
import subprocess

from src.console import console, log_error
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


def crack_handshake(
    handshake_path: str, wordlist_path: str, display_essid: str
) -> str | None:
    try:
        start_time = time.time()

        proc = subprocess.Popen(
            ["aircrack-ng", "-w", wordlist_path, handshake_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding='utf-8',
            errors='replace',
        )

        stdout_lines = []
        while True:
            line = proc.stdout.readline()
            if line:
                stdout_lines.append(line)
                if "KEY FOUND!" in line:
                    break
            if proc.poll() is not None:
                break
            time.sleep(0.05)

        remaining_stdout, _ = proc.communicate()
        stdout_lines.append(remaining_stdout)
        result_stdout = "".join(stdout_lines)

        if proc.returncode != 0 and "KEY FOUND!" not in result_stdout:
            console.print(f"  Failed: aircrack-ng did not find the key.")
            log_error(
                f"Aircrack-ng failed for {os.path.basename(handshake_path)}:\n"
                f"Stdout:\n{result_stdout}"
            )
            return None

        if "KEY FOUND!" in result_stdout:
            match = re.search(r"KEY FOUND!\s*\[\s*(.*?)\s*\]", result_stdout)
            if match:
                password = match.group(1)
                elapsed = time.time() - start_time
                m, s = divmod(int(elapsed), 60)
                time_str = f"{m:02d}:{s:02d}"

                essid_match = re.search(r"SSID:\s*(.*)", result_stdout)
                final_essid = display_essid
                if (
                    essid_match
                    and essid_match.group(1).strip() not in ("", "<hidden>")
                ):
                    final_essid = essid_match.group(1).strip()
                elif final_essid in ("<hidden>",) or final_essid.endswith(
                    "_from_filename"
                ):
                    final_essid = (
                        os.path.basename(handshake_path)
                        .replace(".cap", "")
                        .replace(".pcap", "")
                        + "_determined_final"
                    )

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

                console.print(f"  Saved to: {result_file}")
                return password

        console.print(f"  Password not found in wordlist. Try a larger wordlist.")
        return None

    except Exception as e:
        log_error(f"Critical error during cracking process for {handshake_path}", e)
        console.print(f"  Cracking terminated due to an unexpected error.")
        return None
