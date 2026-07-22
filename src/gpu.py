import platform
import subprocess


def _get_wmic_gpu_output() -> str:
    r = subprocess.run(
        ["wmic", "path", "win32_videocontroller", "get", "name"],
        capture_output=True, text=True, check=False, timeout=5)
    return r.stdout


def _get_powershell_gpu_output() -> str:
    r = subprocess.run(
        ["powershell", "-NoProfile", "-Command",
         "Get-CimInstance Win32_VideoController | Select-Object -ExpandProperty Name"],
        capture_output=True, text=True, check=False, timeout=5)
    if r.returncode != 0 or not r.stdout.strip():
        r = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "Get-WmiObject Win32_VideoController | Select-Object -ExpandProperty Name"],
            capture_output=True, text=True, check=False, timeout=5)
    return r.stdout


def _gpu_in_output(output: str) -> bool:
    brands = ["nvidia", "geforce", "rtx", "gtx", "quadro", "tesla",
              "amd", "radeon", "rx", "firepro"]
    skip = ["intel", "microsoft", "basic display", "vmware", "virtualbox",
            "parsec", "remote"]
    for line in output.splitlines():
        line = line.strip().lower()
        if line and not any(x in line for x in skip):
            if any(b in line for b in brands):
                return True
    return False


def has_discrete_gpu() -> bool:
    system = platform.system()
    try:
        if system == "Windows":
            output = _get_powershell_gpu_output()
            if _gpu_in_output(output):
                return True
            output = _get_wmic_gpu_output()
            if _gpu_in_output(output):
                return True
        elif system == "Linux":
            r = subprocess.run(
                ["lspci"], capture_output=True, text=True, check=False, timeout=5)
            for line in r.stdout.splitlines():
                low = line.lower()
                if any(kw in low for kw in ["vga", "3d", "display"]):
                    brands = ["nvidia", "geforce", "rtx", "gtx", "quadro", "tesla",
                              "amd", "radeon", "rx", "firepro"]
                    if any(b in low for b in brands):
                        return True
    except Exception:
        pass
    return False


def get_gpu_name() -> str | None:
    system = platform.system()
    try:
        if system == "Windows":
            for method in [_get_powershell_gpu_output, _get_wmic_gpu_output]:
                output = method()
                for line in output.splitlines():
                    line = line.strip()
                    if line and "name" not in line.lower():
                        if not any(x in line.lower() for x in ["intel", "microsoft",
                                                               "basic", "vmware",
                                                               "virtualbox", "parsec"]):
                            return line
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
