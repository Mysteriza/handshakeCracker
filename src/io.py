"""File download / extraction helpers (streaming, low-RAM)."""

from __future__ import annotations

import hashlib
import os
import shutil
import sys
import tempfile
import urllib.request
import zipfile

from src.console import colored_log, log_error

_IO_CHUNK = 1 << 20


def download_with_progress(
    url: str, dest: str, label: str = "Downloading", expected_sha256: str | None = None
) -> bool:
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
            with open(dest, "rb") as f:
                for chunk in iter(lambda: f.read(_IO_CHUNK), b""):
                    hasher.update(chunk)
            actual_sha256 = hasher.hexdigest().upper()
            if actual_sha256 != expected_sha256.upper():
                colored_log(
                    "error",
                    f"Checksum verification failed for {label}! Expected {expected_sha256}, got {actual_sha256}.",
                )
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


def extract_local_zip(
    zip_path: str, extract_to: str, subdir: str | None = None
) -> bool:
    try:
        colored_log("info", f"Extracting {os.path.basename(zip_path)}...")
        os.makedirs(extract_to, exist_ok=True)

        with zipfile.ZipFile(zip_path, "r") as zf:
            for member in zf.namelist():
                if subdir and not member.startswith(subdir):
                    continue
                rel_path = member[len(subdir):].lstrip("/") if subdir else member
                if not rel_path:
                    continue
                target = os.path.join(extract_to, rel_path)
                if member.endswith("/"):
                    os.makedirs(target, exist_ok=True)
                else:
                    parent = os.path.dirname(target)
                    if parent:
                        os.makedirs(parent, exist_ok=True)
                    with zf.open(member) as src, open(target, "wb") as dst:
                        shutil.copyfileobj(src, dst, _IO_CHUNK)

        colored_log("success", f"Extracted '{os.path.basename(zip_path)}'.")
        return True
    except KeyboardInterrupt:
        colored_log("warning", "Extraction interrupted by user.")
        return False
    except Exception as e:
        log_error(f"Failed to extract {zip_path}", e)
        return False


def download_wordlist(url: str, dest: str) -> bool:
    result = download_with_progress(url, dest, "Downloading wordlist")
    if result:
        colored_log("success", f"Wordlist ready: {dest}")
        return True
    if os.path.exists(dest):
        try:
            os.remove(dest)
        except OSError:
            pass
    colored_log("error", "Failed to download wordlist. Check your internet connection.")
    return False


def download_and_extract_zip(
    url: str,
    extract_to: str,
    subdir: str | None = None,
    expected_sha256: str | None = None,
) -> bool:
    tmp_path = None
    try:
        colored_log("info", "Downloading aircrack-ng for Windows...")
        colored_log(
            "info", "The aircrack-ng server can be slow; this may take a few minutes."
        )
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
            tmp_path = tmp.name

        if not download_with_progress(
            url, tmp_path, "Downloading aircrack-ng", expected_sha256
        ):
            return False

        colored_log("info", "Extracting...")
        return extract_local_zip(tmp_path, extract_to, subdir)

    except Exception as e:
        log_error("Failed to download/extract aircrack-ng", e)
        colored_log(
            "error", "Failed to set up aircrack-ng. Check your internet connection."
        )
        return False
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


def format_file_size(size_bytes: int) -> str:
    mb = size_bytes / (1024 * 1024)
    if mb >= 1024:
        gb = mb / 1024
        return f"{gb:,.1f} GB"
    return f"{mb:,.1f} MB"
