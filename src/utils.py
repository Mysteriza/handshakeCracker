import os
import re
import sys
import urllib.request
import zipfile

from src.console import colored_log, log_error



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
