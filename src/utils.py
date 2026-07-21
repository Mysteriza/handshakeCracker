import os
import re
import sys
import subprocess
import tempfile
import urllib.request
import zipfile

from src.console import console, colored_log, log_error


def execute_command(command: list[str]) -> subprocess.CompletedProcess | None:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            encoding='utf-8',
            errors='replace',
        )
        if result.returncode != 0:
            error_msg = (
                f"Command failed with exit code {result.returncode}: {' '.join(command)}\n"
                f"Stdout: {result.stdout}\nStderr: {result.stderr}"
            )
            log_error(f"Command execution error: {error_msg}")
        return result
    except FileNotFoundError:
        log_error(f"Command not found: '{command[0]}'. Make sure it's installed and in your PATH.")
        return None
    except Exception as e:
        log_error(f"Unhandled exception during command execution: {' '.join(command)}", e)
        return None


def sanitize_ssid(ssid: str) -> str:
    return re.sub(r'[\\/*?:"<>|]', "", ssid).replace(" ", "_").strip()


def scan_default_directory(directory_path: str) -> list[str]:
    found_files = []
    if not os.path.exists(directory_path):
        colored_log("error", f"Default directory {directory_path} not found.")
        return []

    colored_log("info", f"Scanning directory: {directory_path} for .cap/.pcap files...")
    for root, _, files in os.walk(directory_path):
        for file in files:
            if file.lower().endswith((".cap", ".pcap")):
                full_path = os.path.join(root, file)
                found_files.append(full_path)
    return found_files


def get_essid_from_file_analysis(cap_file: str) -> str:
    essid = os.path.basename(cap_file).replace(".cap", "").replace(".pcap", "")
    try:
        result = execute_command(["aircrack-ng", cap_file])
        if result and result.stdout:
            essid_line_match = re.search(
                r"[\dA-Fa-f:]{17}\s*(.*?)\s+(?:WEP|WPA)", result.stdout
            )
            if essid_line_match:
                found_essid = essid_line_match.group(1).strip()
                if found_essid not in ("", "<hidden>"):
                    return found_essid

            essid_match_summary = re.search(
                r"ESSID:\s*(.*?)(?:\s*\([\dA-Fa-f:]{17}\))?", result.stdout
            )
            if essid_match_summary:
                found_essid_summary = essid_match_summary.group(1).strip()
                if found_essid_summary not in ("", "<hidden>"):
                    return found_essid_summary

            if "ESSID: <hidden>" in result.stdout:
                return "<hidden>"
    except Exception as e:
        log_error(f"Error extracting ESSID for display from {cap_file}", e)

    return essid


def download_with_progress(url: str, dest: str, label: str = "Downloading") -> bool:
    try:
        def report(block_count, block_size, total_size):
            downloaded = block_count * block_size / (1024 * 1024)
            total = total_size / (1024 * 1024)
            sys.stdout.write(f"\r{label}: {downloaded:.1f}MB / {total:.1f}MB")
            sys.stdout.flush()

        urllib.request.urlretrieve(url, dest, report)
        sys.stdout.write("\n")
        return True
    except Exception as e:
        log_error(f"Failed to download {url}", e)
        return False


def download_wordlist(url: str, dest: str) -> bool:
    colored_log("info", "Wordlist not found. Downloading from GitHub...")
    if download_with_progress(url, dest, "Downloading wordlist"):
        colored_log("success", f"Wordlist ready: {dest}")
        return True
    colored_log("error", "Failed to download wordlist. Check your internet connection.")
    return False


def download_and_extract_zip(url: str, extract_to: str, subdir: str | None = None) -> bool:
    tmp_path = None
    try:
        colored_log("info", "Downloading aircrack-ng for Windows...")
        with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as tmp:
            tmp_path = tmp.name

        if not download_with_progress(url, tmp_path, "Downloading aircrack-ng"):
            return False

        colored_log("info", "Extracting...")
        os.makedirs(extract_to, exist_ok=True)

        with zipfile.ZipFile(tmp_path, 'r') as zf:
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

        colored_log("success", f"aircrack-ng extracted to '{extract_to}'.")
        return True

    except Exception as e:
        log_error("Failed to download/extract aircrack-ng", e)
        colored_log("error", "Failed to set up aircrack-ng. Check your internet connection.")
        return False
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)
