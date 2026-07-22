import platform
import subprocess


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
    if r.returncode != 0 or not r.stdout.strip():
        cmd[2] = (
            "Get-WmiObject Win32_VideoController | "
            "Where-Object { $_.ConfigManagerErrorCode -eq 0 } | "
            "Select-Object Name, AdapterRAM | "
            "ConvertTo-Csv -NoTypeInformation"
        )
        r = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=5)

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
    return gpus


def _is_discrete(gpu: dict) -> bool:
    name = gpu["name"].lower()

    if any(x in name for x in _SKIP):
        return False

    if any(x in name for x in _KNOWN_DISCRETE):
        return True

    if "nvidia" in name or "geforce" in name:
        return True

    return False


def has_discrete_gpu() -> bool:
    system = platform.system()
    try:
        if system == "Windows":
            gpus = _get_gpu_list_powershell()
            if not gpus:
                gpus = _get_gpu_list_wmic()
            for gpu in gpus:
                if _is_discrete(gpu):
                    return True
        elif system == "Linux":
            r = subprocess.run(
                ["lspci"], capture_output=True, text=True, check=False, timeout=5)
            for line in r.stdout.splitlines():
                low = line.lower()
                if any(kw in low for kw in ["vga", "3d", "display"]):
                    if any(x in low for x in _KNOWN_DISCRETE):
                        return True
                    if "nvidia" in low or "geforce" in low:
                        return True
    except Exception:
        pass
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
                    return gpu["name"]
            for gpu in gpus:
                low = gpu["name"].lower()
                if not any(x in low for x in _SKIP):
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
