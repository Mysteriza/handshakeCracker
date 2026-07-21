import os
import re
import sys
import tempfile
import urllib.request
import zipfile

from src.console import console, colored_log, log_error



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
        colored_log("info", "The aircrack-ng server can be slow; this may take a few minutes.")
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
