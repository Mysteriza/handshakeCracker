import os
import platform
import subprocess
import sys

from rich.panel import Panel
from rich.text import Text

from src.console import console, colored_log, log_error
from src.config import (
    HANDSHAKES_DIR, RESULTS_DIR, WORDLIST_NAME, WORDLIST_URL,
    AIRCRACK_WIN_URL, BIN_DIR, DEPS_DIR, AIRCRACK_ZIP_NAME,
)
from src.utils import download_wordlist, download_and_extract_zip, extract_local_zip


def _find_exe_in_path(exe: str) -> str | None:
    for path in os.environ.get("PATH", "").split(os.pathsep):
        candidate = os.path.join(path.strip('"'), exe)
        if os.path.isfile(candidate):
            return candidate
    return None


def _find_aircrack_anywhere() -> str | None:
    system = platform.system()
    exe = "aircrack-ng.exe" if system == "Windows" else "aircrack-ng"
    found = _find_exe_in_path(exe)
    if found:
        return found

    root = os.path.dirname(os.path.abspath(__file__))
    local_paths = [
        os.path.join(root, "..", exe),
        os.path.join(root, "..", BIN_DIR, exe),
    ]

    if system == "Windows":
        local_paths += [
            os.path.join(os.environ.get("PROGRAMFILES", "C:\\Program Files"), "aircrack-ng", "bin", exe),
            os.path.join(os.environ.get("PROGRAMFILES(X86)", "C:\\Program Files (x86)"), "aircrack-ng", "bin", exe),
            os.path.join(os.environ.get("LOCALAPPDATA", ""), "aircrack-ng", "bin", exe),
        ]

    for p in local_paths:
        resolved = os.path.abspath(p)
        if os.path.isfile(resolved):
            return resolved
    return None


def _add_parent_to_path(found_path: str):
    parent = os.path.dirname(os.path.abspath(found_path))
    if parent not in os.environ.get("PATH", ""):
        os.environ["PATH"] = parent + os.pathsep + os.environ.get("PATH", "")


def ensure_aircrack() -> bool:
    try:
        found = _find_aircrack_anywhere()
        if found:
            _add_parent_to_path(found)
            return True

        system = platform.system()
        if system == "Windows":
            root = os.path.dirname(os.path.abspath(__file__))
            bin_path = os.path.abspath(os.path.join(root, "..", BIN_DIR))

            local_zip = os.path.abspath(os.path.join(root, "..", DEPS_DIR, AIRCRACK_ZIP_NAME))
            if os.path.isfile(local_zip):
                colored_log("info", "Found local aircrack-ng ZIP.")
                if extract_local_zip(local_zip, bin_path, "aircrack-ng-1.7-win/bin"):
                    found = _find_aircrack_anywhere()
                    if found:
                        _add_parent_to_path(found)
                        return True
                colored_log("warning", "Local ZIP extraction failed — trying download.")

            if download_and_extract_zip(AIRCRACK_WIN_URL, bin_path, "aircrack-ng-1.7-win/bin"):
                found = _find_aircrack_anywhere()
                if found:
                    _add_parent_to_path(found)
                    return True
            colored_log("error", "Could not download aircrack-ng.")
            return False

        elif system == "Linux":
            colored_log("info", "Installing aircrack-ng via apt-get...")
            try:
                subprocess.run(
                    ["sudo", "apt-get", "install", "-y", "aircrack-ng"],
                    check=True, capture_output=True, text=True,
                )
                colored_log("success", "aircrack-ng installed.")
                found = _find_aircrack_anywhere()
                if found:
                    _add_parent_to_path(found)
                    return True
            except (subprocess.CalledProcessError, FileNotFoundError):
                pass
            colored_log("error", "Could not install aircrack-ng automatically.")
            colored_log("info", "Install manually: sudo apt-get install aircrack-ng")
            return False

        else:
            colored_log("error", f"Unsupported OS: {system}. Install aircrack-ng manually.")
            return False

    except Exception as e:
        log_error("Error during aircrack-ng setup", e)
        colored_log("error", "Could not set up aircrack-ng.")
        return False


def show_banner():
    console.print(
        Panel(
            Text("Wi-Fi Handshake Cracker", justify="center"),
            subtitle="Audit your WPA/WPA2 handshakes",
            border_style="blue",
            padding=(1, 4),
        )
    )
    console.print("\n[cyan]Initializing...[/cyan]")


def ensure_directories() -> bool:
    try:
        os.makedirs(RESULTS_DIR, exist_ok=True)
    except (OSError, PermissionError):
        colored_log("error", f"Cannot create results directory: {RESULTS_DIR}")
        return False

    if not os.path.exists(HANDSHAKES_DIR):
        try:
            os.makedirs(HANDSHAKES_DIR)
        except (OSError, PermissionError):
            colored_log("warning", f"Cannot create '{HANDSHAKES_DIR}' dir.")
            return True

    has_cap = any(
        f.lower().endswith(('.cap', '.pcap'))
        for f in os.listdir(HANDSHAKES_DIR)
    )
    if not has_cap:
        colored_log("warning", f"No .cap/.pcap files found in '{HANDSHAKES_DIR}'.")

    return True


def ensure_wordlist() -> bool:
    wordlist_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", WORDLIST_NAME
    )
    if os.path.exists(wordlist_path):
        return True

    if download_wordlist(WORDLIST_URL, wordlist_path):
        return True

    return False


def ensure_python_dependencies() -> bool:
    """Install required Python packages from requirements.txt if missing."""
    req_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "requirements.txt")
    if not os.path.isfile(req_path):
        colored_log("warning", "requirements.txt not found, skipping Python dependency check.")
        return True

    try:
        import rich
        import prompt_toolkit
        import scapy
        return True
    except ImportError:
        pass

    colored_log("info", "Installing Python dependencies from requirements.txt...")

    def _pip_install(req_path: str) -> bool:
        """Install with --user first, fallback to --break-system-packages on PEP 668."""
        base_cmd = [sys.executable, "-m", "pip", "install", "--user", "-r", req_path]
        try:
            subprocess.check_call(base_cmd, capture_output=True, text=True)
            return True
        except subprocess.CalledProcessError as e:
            err = (e.stderr or "").lower()
            if "externally-managed" in err:
                colored_log("warning", "PEP 668 detected — retrying with --break-system-packages...")
                try:
                    subprocess.check_call(base_cmd + ["--break-system-packages"],
                                          capture_output=True, text=True)
                    return True
                except subprocess.CalledProcessError:
                    return False
            return False
        except Exception:
            return False

    if _pip_install(req_path):
        colored_log("success", "Python dependencies installed.")
        return True

    log_error("Failed to install Python dependencies")
    colored_log("error", "Install manually: pip install --user -r requirements.txt")
    colored_log("info", "Or if blocked by PEP 668: pip install --break-system-packages -r requirements.txt")
    return False


def ensure_p7zip() -> bool:
    """Ensure 7z is available on Linux for hashcat .7z extraction."""
    if platform.system() != "Linux":
        return True
    try:
        subprocess.run(["7z"], capture_output=True, check=False)
        return True
    except FileNotFoundError:
        colored_log("info", "Installing p7zip-full for hashcat extraction...")
        try:
            subprocess.run(
                ["sudo", "apt-get", "install", "-y", "p7zip-full"],
                check=True, capture_output=True, text=True,
            )
            colored_log("success", "p7zip-full installed.")
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            colored_log("warning", "Could not install p7zip-full. Hashcat extraction may fail.")
            return False


def auto_setup() -> dict:
    """Run full auto-setup. Returns dict with availability flags."""
    show_banner()

    ensure_python_dependencies()

    aircrack_ok = ensure_aircrack()
    dirs_ok = ensure_directories()
    wordlist_ok = ensure_wordlist()

    # Hashcat setup (optional — fallback to aircrack-ng if it fails)
    ensure_p7zip()
    try:
        from src.hashcat_cracker import ensure_hashcat
        hashcat_ok = ensure_hashcat()
    except Exception as e:
        log_debug(f"auto_setup: hashcat setup skipped ({e})")
        hashcat_ok = False

    if not aircrack_ok and not hashcat_ok:
        colored_log("error", "No cracking tool available (aircrack-ng or hashcat).")
        return {"aircrack_available": False, "hashcat_available": False}

    return {
        "aircrack_available": aircrack_ok,
        "hashcat_available": hashcat_ok,
        "directories_ready": dirs_ok,
        "wordlist_ready": wordlist_ok,
    }
