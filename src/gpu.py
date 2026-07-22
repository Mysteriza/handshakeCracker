import platform
import subprocess

from src.console import log_error


_KNOWN_DISCRETE = ["rtx", "gtx", "quadro", "tesla", "rx", "firepro", "pro wx"]
_SKIP = ["intel", "microsoft", "basic display", "vmware", "virtualbox",
         "parsec", "remote"]


def _get_gpu_list_powershell() -> list[dict]:
    cmd = [
        "powershell", "-NoProfile", "-Command",
        "Get-CimInstance Win32_VideoController | "
        "Where-Object { $_.ConfigManagerErrorCode -eq 0 } | "
        "Select-Object Name, AdapterRAM | "
        "ConvertTo-Csv -NoTypeInformation"
    ]
    r = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=5)
    method = "PowerShell (Get-CimInstance)"
    if r.returncode != 0 or not r.stdout.strip():
        cmd[2] = (
            "Get-WmiObject Win32_VideoController | "
            "Where-Object { $_.ConfigManagerErrorCode -eq 0 } | "
            "Select-Object Name, AdapterRAM | "
            "ConvertTo-Csv -NoTypeInformation"
        )
        r = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=5)
        method = "PowerShell (Get-WmiObject)"

    log_error(f"GPU detection: queried via {method}")

    gpus = []
    lines = r.stdout.strip().splitlines()
    for line in lines[1:]:  # skip CSV header
        parts = [x.strip('"') for x in line.split(',')]
        if len(parts) >= 2 and parts[0]:
            name = parts[0].strip()
            ram_str = parts[1].strip() if parts[1] else "0"
            try:
                ram_bytes = int(ram_str) if ram_str.isdigit() else 0
            except ValueError:
                ram_bytes = 0
            gpus.append({"name": name, "ram_bytes": ram_bytes})
            log_error(f"GPU detection: found \"{name}\" (VRAM: {ram_bytes / (1024**3):.2f} GB)")
    return gpus


def _get_gpu_list_wmic() -> list[dict]:
    r = subprocess.run(
        ["wmic", "path", "win32_videocontroller", "get", "name", "/format:csv"],
        capture_output=True, text=True, check=False, timeout=5)
    gpus = []
    for line in r.stdout.splitlines():
        parts = line.split(",")
        if len(parts) >= 2:
            name = parts[-1].strip()
            if name and name.lower() != "name":
                gpus.append({"name": name, "ram_bytes": 0})
                log_error(f"GPU detection (wmic): found \"{name}\" (VRAM: N/A)")
    return gpus


def _is_discrete(gpu: dict) -> bool:
    name = gpu["name"].lower()
    reason = ""

    if any(x in name for x in _SKIP):
        reason = f"skipped (matched skip list)"
        log_error(f"GPU detection: \"{gpu['name']}\" -> {reason}")
        return False

    if any(x in name for x in _KNOWN_DISCRETE):
        matched = [x for x in _KNOWN_DISCRETE if x in name][0]
        reason = f"discrete (matched \"{matched}\")"
        log_error(f"GPU detection: \"{gpu['name']}\" -> {reason}")
        return True

    if "nvidia" in name or "geforce" in name:
        reason = f"discrete (NVIDIA brand)"
        log_error(f"GPU detection: \"{gpu['name']}\" -> {reason}")
        return True

    log_error(f"GPU detection: \"{gpu['name']}\" -> integrated (no matching pattern)")
    return False


def has_discrete_gpu() -> bool:
    system = platform.system()
    log_error(f"GPU detection: OS={system}")
    try:
        if system == "Windows":
            gpus = _get_gpu_list_powershell()
            method = "PowerShell"
            if not gpus:
                gpus = _get_gpu_list_wmic()
                method = "WMIC"
            log_error(f"GPU detection: {method} returned {len(gpus)} GPU(s)")
            for gpu in gpus:
                if _is_discrete(gpu):
                    log_error(f"GPU detection: RESULT = discrete GPU found")
                    return True
            log_error(f"GPU detection: RESULT = no discrete GPU found")
        elif system == "Linux":
            r = subprocess.run(
                ["lspci"], capture_output=True, text=True, check=False, timeout=5)
            log_error(f"GPU detection (lspci):\n{r.stdout.strip()[:500]}")
            for line in r.stdout.splitlines():
                low = line.lower()
                if any(kw in low for kw in ["vga", "3d", "display"]):
                    if any(x in low for x in _KNOWN_DISCRETE):
                        log_error(f"GPU detection: RESULT = discrete GPU found via lspci")
                        return True
                    if "nvidia" in low or "geforce" in low:
                        log_error(f"GPU detection: RESULT = discrete GPU found via lspci")
                        return True
            log_error(f"GPU detection: RESULT = no discrete GPU found via lspci")
    except Exception as e:
        log_error(f"GPU detection: EXCEPTION = {e}")
    return False


def get_gpu_name() -> str | None:
    system = platform.system()
    try:
        if system == "Windows":
            gpus = _get_gpu_list_powershell()
            if not gpus:
                gpus = _get_gpu_list_wmic()
            for gpu in gpus:
                if _is_discrete(gpu):
                    log_error(f"GPU detection: selected \"{gpu['name']}\"")
                    return gpu["name"]
            for gpu in gpus:
                low = gpu["name"].lower()
                if not any(x in low for x in _SKIP):
                    log_error(f"GPU detection: selected (fallback) \"{gpu['name']}\"")
                    return gpu["name"]
        elif system == "Linux":
            r = subprocess.run(
                ["lspci", "-vnn"], capture_output=True, text=True, check=False, timeout=5)
            for line in r.stdout.splitlines():
                low = line.lower()
                if any(kw in low for kw in ["vga", "3d", "display"]):
                    return line.strip()
    except Exception:
        pass
    return None
