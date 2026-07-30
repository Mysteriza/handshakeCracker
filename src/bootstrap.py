import subprocess
import sys


def pip_install_requirements(req_path: str) -> bool:
    base_cmd = [sys.executable, "-m", "pip", "install", "--user", "-r", req_path]
    try:
        subprocess.run(base_cmd, check=True, capture_output=True, text=True)
        return True
    except subprocess.CalledProcessError as e:
        combined = ((e.stderr or "") + (e.stdout or "")).lower()
        if "externally-managed" in combined:
            try:
                subprocess.run(base_cmd + ["--break-system-packages"], check=True, capture_output=True, text=True)
                return True
            except subprocess.CalledProcessError:
                return False
        return False
    except Exception:
        return False
