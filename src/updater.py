import base64
import json
import os
import subprocess
import sys
import tempfile
import urllib.request
import zipfile

from src.console import console, colored_log

_ZIP_URL = "https://github.com/Mysteriza/handshakeCracker/archive/main.zip"

_remote_ver: str | None = None
_local_ver: str | None = None


def _read_local_version() -> str | None:
    try:
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "version.txt")) as f:
            return f.read().strip()
    except Exception:
        return None


def _put_local_version(version: str):
    try:
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "version.txt"), "w") as f:
            f.write(version.strip() + "\n")
    except Exception:
        pass


def _fetch_remote_version() -> str | None:
    try:
        r = urllib.request.urlopen(
            "https://api.github.com/repos/Mysteriza/handshakeCracker/contents/version.txt",
            timeout=10,
        )
        data = json.loads(r.read().decode("utf-8"))
        import base64
        return base64.b64decode(data["content"]).decode("utf-8").strip()
    except Exception:
        return None


def _git_update(root: str) -> bool:
    try:
        r = subprocess.run(
            ["git", "fetch", "origin", "main"],
            capture_output=True, text=True, timeout=15, check=False, cwd=root,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
        )
        if r.returncode != 0:
            return False

        local = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=5, check=False, cwd=root,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
        )
        remote = subprocess.run(
            ["git", "rev-parse", "origin/main"],
            capture_output=True, text=True, timeout=5, check=False, cwd=root,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
        )
        if local.returncode != 0 or remote.returncode != 0:
            return False
        if local.stdout.strip() == remote.stdout.strip():
            return False

        log = subprocess.run(
            ["git", "log", "--oneline", "--no-decorate",
             f"{local.stdout.strip()}..{remote.stdout.strip()}"],
            capture_output=True, text=True, timeout=5, check=False, cwd=root,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
        )
        if log.returncode == 0 and log.stdout.strip():
            colored_log("info", "Updates available:")
            for line in log.stdout.strip().splitlines():
                console.print(f"  {line}")

        colored_log("info", "Auto-updating via git...")
        pull = subprocess.run(
            ["git", "pull", "--ff-only", "origin", "main"],
            capture_output=True, text=True, timeout=30, check=False, cwd=root,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
        )
        if pull.returncode != 0:
            return False
        return True
    except Exception:
        return False


def _zip_update(root: str, remote_ver: str) -> bool:
    colored_log("info", "Downloading latest version...")
    tmp_zip = os.path.join(tempfile.gettempdir(), "handshakeCracker_update.zip")
    try:
        urllib.request.urlretrieve(_ZIP_URL, tmp_zip)
    except Exception:
        return False

    try:
        extract_to = os.path.join(tempfile.gettempdir(), "handshakeCracker_update_extract")
        if os.path.exists(extract_to):
            import shutil
            shutil.rmtree(extract_to, ignore_errors=True)
        os.makedirs(extract_to, exist_ok=True)

        with zipfile.ZipFile(tmp_zip, 'r') as zf:
            zf.extractall(extract_to)

        src_dir = os.path.join(extract_to, "handshakeCracker-main")
        if not os.path.isdir(src_dir):
            return False

        import shutil
        items = ["main.py", "requirements.txt", "README.md", "version.txt"]
        for name in items:
            src = os.path.join(src_dir, name)
            if os.path.isfile(src):
                shutil.copy2(src, os.path.join(root, name))

        src_src = os.path.join(src_dir, "src")
        dst_src = os.path.join(root, "src")
        for fname in os.listdir(src_src):
            sf = os.path.join(src_src, fname)
            if os.path.isfile(sf):
                shutil.copy2(sf, os.path.join(dst_src, fname))

        return True
    finally:
        try:
            os.unlink(tmp_zip)
        except OSError:
            pass


def _parse_ver(v: str) -> tuple:
    try:
        return tuple(int(x) for x in v.split("."))
    except Exception:
        return (0,)


def check_for_updates() -> bool:
    global _remote_ver, _local_ver
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    _local_ver = _read_local_version()
    _remote_ver = _fetch_remote_version()

    if _remote_ver is None:
        return False

    if _local_ver is None:
        return False

    if _parse_ver(_remote_ver) <= _parse_ver(_local_ver):
        return False

    colored_log("info", f"Update found: v{_local_ver or '?'} -> v{_remote_ver}")

    git_dir = os.path.join(root, ".git")
    if os.path.isdir(git_dir) and _git_update(root):
        _put_local_version(_remote_ver)
        console.print("\n  Updated to the latest version!")
        console.print("  Please restart the program.\n")
        return True

    colored_log("info", "Trying direct download...")
    if _zip_update(root, _remote_ver):
        _put_local_version(_remote_ver)
        console.print("\n  Updated to the latest version!")
        console.print("  Please restart the program.\n")
        return True

    colored_log("warning", "Auto-update failed. Download manually from GitHub.")
    return False


def show_version_info():
    v = _local_ver or _read_local_version()
    if not v:
        return
    if _remote_ver is None:
        colored_log("info", f"Current version: v{v}")
    elif _parse_ver(_remote_ver) > _parse_ver(v):
        colored_log("info", f"Update available: v{v} -> v{_remote_ver}. Restart to update.")
    elif _parse_ver(_remote_ver) < _parse_ver(v):
        colored_log("info", f"You are on a development version (v{v}).")
    else:
        colored_log("info", f"You are on the latest version (v{v}).")
