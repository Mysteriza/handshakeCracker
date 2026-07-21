import os
import re
import time
import subprocess

from rich.progress import Progress, SpinnerColumn, TextColumn

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


def parse_aircrack_failure_summary(output: str) -> dict:
    parsed_info = {
        "keys_tested": "N/A",
        "time_left": "N/A",
        "percentage": "N/A",
        "current_passphrase": "N/A",
        "master_key": "N/A",
        "transient_key": "N/A",
        "eapol_hmac": "N/A",
    }

    lines = output.splitlines()
    for i in range(len(lines) - 1, -1, -1):
        line = lines[i]

        if "keys tested" in line and parsed_info["keys_tested"] == "N/A":
            match = re.search(r"(\d+)/(\d+)\s+keys tested\s+\(([\d.]+ k/s)\)", line)
            if match:
                parsed_info["keys_tested"] = (
                    f"{match.group(1)}/{match.group(2)} keys tested ({match.group(3)})"
                )
            if i + 1 < len(lines):
                time_percent_line = lines[i + 1]
                time_match = re.search(
                    r"Time left:\s*(.*?)\s*([\d.]+\%)", time_percent_line
                )
                if time_match:
                    parsed_info["time_left"] = time_match.group(1).strip()
                    parsed_info["percentage"] = time_match.group(2).strip()
            continue

        if "Current passphrase:" in line and parsed_info["current_passphrase"] == "N/A":
            match = re.search(r"Current passphrase:\s*(.*)", line)
            if match:
                parsed_info["current_passphrase"] = match.group(1).strip()
            continue

        if "Master Key" in line and parsed_info["master_key"] == "N/A":
            match = re.search(r"Master Key\s*:\s*(.*)", line)
            if match:
                key_hex = match.group(1).strip()
                collected = [key_hex]
                for j in range(i + 1, len(lines)):
                    nl = lines[j].strip()
                    if re.match(r"([\dA-Fa-f]{2}(?:\s[\dA-Fa-f]{2})*){1,16}", nl):
                        collected.append(nl)
                    else:
                        break
                parsed_info["master_key"] = "\n    ".join(collected)
            continue

        if "Transient Key" in line and parsed_info["transient_key"] == "N/A":
            match = re.search(r"Transient Key\s*:\s*(.*)", line)
            if match:
                key_hex = match.group(1).strip()
                collected = [key_hex]
                for j in range(i + 1, len(lines)):
                    nl = lines[j].strip()
                    if re.match(r"([\dA-Fa-f]{2}(?:\s[\dA-Fa-f]{2})*){1,16}", nl):
                        collected.append(nl)
                    else:
                        break
                parsed_info["transient_key"] = "\n    ".join(collected)
            continue

        if "EAPOL HMAC" in line and parsed_info["eapol_hmac"] == "N/A":
            match = re.search(r"EAPOL HMAC\s*:\s*(.*)", line)
            if match:
                parsed_info["eapol_hmac"] = match.group(1).strip()
            continue

    return parsed_info


def crack_handshake(
    handshake_path: str, wordlist_path: str, display_essid: str
) -> str | None:
    print()
    console.print(f"[cyan]  Wordlist:[/cyan] {os.path.basename(wordlist_path)}")

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

        with Progress(
            SpinnerColumn("dots", style="cyan"),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
            console=console,
        ) as progress:
            task = progress.add_task(messages[0], total=None)

            start_time = time.time()
            last_switch = start_time

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

                now = time.time()
                if now - last_switch >= 3:
                    msg_idx = (msg_idx + 1) % len(messages)
                    progress.update(task, description=messages[msg_idx])
                    last_switch = now

                if proc.poll() is not None:
                    break
                time.sleep(0.05)

            remaining_stdout, _ = proc.communicate()
            stdout_lines.append(remaining_stdout)
            result_stdout = "".join(stdout_lines)
            progress.remove_task(task)

        if proc.returncode != 0 and "KEY FOUND!" not in result_stdout:
            console.print(f"  [red]Failed:[/red] aircrack-ng did not find the key.")
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

                console.print(f"\n  [green]Password Found[/green]")
                console.print(f"  [green]Network:[/green] {final_essid}")
                console.print(f"  [green]Password:[/green] {password}")
                console.print(f"  [dim]Time:[/dim] {time_str}")

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

                console.print(f"  [dim]Saved to:[/dim] {result_file}")
                return password

        console.print(f"  [red]Password not found in wordlist.[/red] "
                      f"Try a larger wordlist.")
        return None

    except Exception as e:
        log_error(f"Critical error during cracking process for {handshake_path}", e)
        console.print(f"  [red]Cracking terminated due to an unexpected error.[/red]")
        return None
