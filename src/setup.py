import os
import platform
import subprocess
import urllib.error
import urllib.request

from rich.panel import Panel
from rich.text import Text

from src.bootstrap import pip_install_requirements
from src.config import (
    AIRCRACK_WIN_SHA256,
    AIRCRACK_WIN_URL,
    AIRCRACK_ZIP_NAME,
    BIN_DIR,
    DEPS_DIR,
    HANDSHAKES_DIR,
    HCOV_DIR,
    RESULTS_DIR,
    WORDLIST_ETAG_FILE,
    WORDLIST_NAME,
    WORDLIST_URL,
)
from src.console import colored_log, console, log_debug, log_error
from src.io import download_and_extract_zip, download_wordlist, extract_local_zip
from src.utils import find_exe_in_path as _find_exe_in_path

_aircrack_path_cache = None


def _find_aircrack_anywhere() -> str | None:
    global _aircrack_path_cache
    if _aircrack_path_cache:
        return _aircrack_path_cache

    system = platform.system()
    exe = "aircrack-ng.exe" if system == "Windows" else "aircrack-ng"
    found = _find_exe_in_path(exe)
    if found:
        _aircrack_path_cache = found
        return found

    root = os.path.dirname(os.path.abspath(__file__))
    local_paths = [
        os.path.join(root, "..", exe),
        os.path.join(root, "..", BIN_DIR, exe),
    ]

    if system == "Windows":
        local_paths += [
            os.path.join(
                os.environ.get("PROGRAMFILES", "C:\\Program Files"),
                "aircrack-ng",
                "bin",
                exe,
            ),
            os.path.join(
                os.environ.get("PROGRAMFILES(X86)", "C:\\Program Files (x86)"),
                "aircrack-ng",
                "bin",
                exe,
            ),
            os.path.join(os.environ.get("LOCALAPPDATA", ""), "aircrack-ng", "bin", exe),
        ]

    for p in local_paths:
        resolved = os.path.abspath(p)
        if os.path.isfile(resolved):
            _aircrack_path_cache = resolved
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

            local_zip = os.path.abspath(
                os.path.join(root, "..", DEPS_DIR, AIRCRACK_ZIP_NAME)
            )
            if os.path.isfile(local_zip):
                colored_log("info", "Found local aircrack-ng ZIP.")
                if extract_local_zip(local_zip, bin_path, "aircrack-ng-1.7-win/bin"):
                    found = _find_aircrack_anywhere()
                    if found:
                        _add_parent_to_path(found)
                        return True
                colored_log("warning", "Local ZIP extraction failed — trying download.")

            if download_and_extract_zip(
                AIRCRACK_WIN_URL,
                bin_path,
                "aircrack-ng-1.7-win/bin",
                AIRCRACK_WIN_SHA256,
            ):
                found = _find_aircrack_anywhere()
                if found:
                    _add_parent_to_path(found)
                    return True
            colored_log("error", "Could not download aircrack-ng.")
            return False

        elif system == "Linux":
            has_apt = _find_exe_in_path("apt-get") is not None
            has_pacman = _find_exe_in_path("pacman") is not None

            if has_apt:
                cmd = ["sudo", "apt-get", "install", "-y", "aircrack-ng"]
            elif has_pacman:
                cmd = ["sudo", "pacman", "-S", "--noconfirm", "aircrack-ng"]
            else:
                colored_log(
                    "error",
                    "Unsupported package manager. Install manually: aircrack-ng",
                )
                return False

            colored_log("info", f"Installing aircrack-ng: {' '.join(cmd)}")
            try:
                subprocess.run(
                    cmd, check=True, capture_output=True, text=True, timeout=120
                )
                colored_log("success", "aircrack-ng installed.")
                found = _find_aircrack_anywhere()
                if found:
                    _add_parent_to_path(found)
                    return True
            except subprocess.TimeoutExpired:
                colored_log(
                    "error",
                    f"Instalasi butuh sudo password, jalankan manual: {' '.join(cmd)}",
                )
                return False
            except (subprocess.CalledProcessError, FileNotFoundError):
                pass
            colored_log("error", "Could not install aircrack-ng automatically.")
            colored_log("info", f"Install manually: {' '.join(cmd)}")
            return False

        else:
            colored_log(
                "error", f"Unsupported OS: {system}. Install aircrack-ng manually."
            )
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

    for directory in [RESULTS_DIR, HANDSHAKES_DIR, BIN_DIR, HCOV_DIR]:
        try:
            os.makedirs(directory, exist_ok=True)
        except (OSError, PermissionError):
            if directory == RESULTS_DIR:
                colored_log("error", f"Cannot create results directory: {RESULTS_DIR}")
                return False
            else:
                colored_log("warning", f"Cannot create directory: {directory}")

    try:
        has_cap = any(
            f.lower().endswith((".cap", ".pcap")) for f in os.listdir(HANDSHAKES_DIR)
        )
    except OSError:
        has_cap = False
    if not has_cap:
        colored_log("warning", f"No .cap/.pcap files found in '{HANDSHAKES_DIR}'.")

    return True


def ensure_wordlist() -> bool:
    wordlist_path = os.path.normpath(
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", WORDLIST_NAME)
    )
    etag_path = os.path.normpath(
        os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "..", WORDLIST_ETAG_FILE
        )
    )

    colored_log("info", "Checking for wordlist updates...")
    try:
        req = urllib.request.Request(WORDLIST_URL, method="HEAD")
        with urllib.request.urlopen(req, timeout=10) as response:
            remote_etag = response.headers.get("ETag")

        local_etag = None
        if os.path.exists(etag_path):
            with open(etag_path) as f:
                local_etag = f.read().strip()

        if (
            os.path.exists(wordlist_path)
            and local_etag == remote_etag
            and remote_etag is not None
        ):
            colored_log("success", "Wordlist is up to date.")
            return True

        colored_log("info", "New wordlist version found or missing, downloading...")
        if download_wordlist(WORDLIST_URL, wordlist_path):
            if remote_etag:
                with open(etag_path, "w") as f:
                    f.write(remote_etag)
            return True

    except urllib.error.URLError as e:
        colored_log(
            "warning", "No internet connection detected (or GitHub is unreachable)."
        )
        log_debug(f"ensure_wordlist network error: {e}")
        if os.path.exists(wordlist_path):
            colored_log("info", "Continuing in offline mode with existing wordlist.")
            return True
    except Exception as e:
        colored_log("warning", f"Failed to check for wordlist updates: {e}")
        # Fallback to checking if file exists
        if os.path.exists(wordlist_path):
            return True

    return False


def ensure_python_dependencies() -> bool:
    """Install required Python packages from requirements.txt if missing."""
    req_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "requirements.txt"
    )
    if not os.path.isfile(req_path):
        colored_log(
            "warning", "requirements.txt not found, skipping Python dependency check."
        )
        return True

    try:
        import prompt_toolkit  # noqa: F401
        import rich  # noqa: F401
        import scapy  # noqa: F401

        return True
    except ImportError:
        pass

    colored_log("info", "Installing Python dependencies from requirements.txt...")

    if pip_install_requirements(req_path):
        colored_log("success", "Python dependencies installed.")
        return True

    log_error("Failed to install Python dependencies")
    colored_log("error", "Install manually: pip install --user -r requirements.txt")
    colored_log(
        "info",
        "Or if blocked by PEP 668: pip install --break-system-packages -r requirements.txt",
    )
    return False


def ensure_p7zip() -> bool:
    """Ensure 7z is available on Linux for hashcat .7z extraction."""
    if platform.system() != "Linux":
        return True
    try:
        subprocess.run(["7z"], capture_output=True, check=False)
        return True
    except FileNotFoundError:
        has_apt = _find_exe_in_path("apt-get") is not None
        has_pacman = _find_exe_in_path("pacman") is not None

        if has_apt:
            cmd = ["sudo", "apt-get", "install", "-y", "p7zip-full"]
        elif has_pacman:
            cmd = ["sudo", "pacman", "-S", "--noconfirm", "p7zip"]
        else:
            colored_log("error", "Unsupported package manager. Install manually: p7zip")
            return False

        colored_log("info", f"Installing p7zip: {' '.join(cmd)}")
        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=120)
            colored_log("success", "p7zip installed.")
            return True
        except subprocess.TimeoutExpired:
            colored_log(
                "error",
                f"Instalasi butuh sudo password, jalankan manual: {' '.join(cmd)}",
            )
            return False
        except (subprocess.CalledProcessError, FileNotFoundError):
            colored_log(
                "warning", "Could not install p7zip. Hashcat extraction may fail."
            )
            return False


def _gpu_cache_path() -> str:
    return os.path.join(BIN_DIR, ".gpu_cache")


def _read_gpu_cache() -> tuple[str | None, bool] | None:
    try:
        path = _gpu_cache_path()
        if not os.path.exists(path):
            return None
        with open(path, encoding="utf-8") as f:
            parts = f.read().strip().split("|")
        if len(parts) != 2:
            return None
        return (parts[0] or None, parts[1] == "1")
    except OSError:
        return None


def _write_gpu_cache(name: str | None, is_discrete: bool):
    try:
        os.makedirs(BIN_DIR, exist_ok=True)
        with open(_gpu_cache_path(), "w", encoding="utf-8") as f:
            f.write(f"{name or ''}|{1 if is_discrete else 0}")
    except OSError:
        pass


def _detect_gpu_cached() -> tuple[str | None, bool]:
    cached = _read_gpu_cache()
    if cached is not None:
        log_debug(f"auto_setup: using cached GPU info: {cached[0]}")
        return cached
    try:
        from src.gpu import detect_gpu

        result = detect_gpu()
        _write_gpu_cache(result[0], result[1])
        return result
    except Exception as e:
        log_debug(f"auto_setup: GPU detection skipped ({e})")
        return None, False


def auto_setup() -> dict:
    """Run full auto-setup. Returns dict with availability flags."""
    from concurrent.futures import ThreadPoolExecutor

    show_banner()

    ensure_python_dependencies()
    dirs_ok = ensure_directories()

    with ThreadPoolExecutor(max_workers=3) as pool:
        fut_aircrack = pool.submit(ensure_aircrack)
        fut_p7zip_hashcat = pool.submit(_ensure_p7zip_then_hashcat)
        fut_wordlist = pool.submit(ensure_wordlist)
        aircrack_ok = fut_aircrack.result()
        hashcat_ok = fut_p7zip_hashcat.result()
        wordlist_ok = fut_wordlist.result()

    # GPU detection (cached; only when hashcat is available)
    gpu_name: str | None = None
    gpu_is_discrete = False
    if hashcat_ok:
        gpu_name, gpu_is_discrete = _detect_gpu_cached()

    if not aircrack_ok and not hashcat_ok:
        colored_log("error", "No cracking tool available (aircrack-ng or hashcat).")
        return {"aircrack_available": False, "hashcat_available": False}

    return {
        "aircrack_available": aircrack_ok,
        "hashcat_available": hashcat_ok,
        "gpu_name": gpu_name,
        "gpu_is_discrete": gpu_is_discrete,
        "directories_ready": dirs_ok,
        "wordlist_ready": wordlist_ok,
    }


def _ensure_p7zip_then_hashcat() -> bool:
    ensure_p7zip()
    try:
        from src.hashcat import ensure_hashcat

        return bool(ensure_hashcat())
    except Exception as e:
        log_debug(f"auto_setup: hashcat setup skipped ({e})")
        return False
