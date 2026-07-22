import os
import subprocess
import sys

from src.console import console, colored_log


def _get_repo_root() -> str | None:
    try:
        r = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, timeout=5, check=False,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
        )
        if r.returncode == 0:
            return r.stdout.strip()
    except Exception:
        pass
    return None


def check_for_updates() -> bool:
    root = _get_repo_root()
    if not root:
        return False

    try:
        r = subprocess.run(
            ["git", "fetch", "origin", "main"],
            capture_output=True, text=True, timeout=15, check=False,
            cwd=root,
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

        colored_log("info", "Auto-updating...")
        pull = subprocess.run(
            ["git", "pull", "--ff-only", "origin", "main"],
            capture_output=True, text=True, timeout=30, check=False, cwd=root,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
        )
        if pull.returncode != 0:
            colored_log("warning", "Auto-update failed. Update manually: git pull")
            return False

        console.print("\n  Updated to the latest version!")
        console.print("  Please restart the program.\n")
        return True

    except Exception:
        return False
