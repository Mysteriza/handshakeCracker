import platform
import subprocess


def has_discrete_gpu() -> bool:
    system = platform.system()
    brands = ["nvidia", "geforce", "rtx", "gtx", "quadro", "tesla",
              "amd", "radeon", "rx", "pro", "firepro"]
    skip = ["intel", "microsoft", "basic display", "vmware", "virtualbox",
            "parsec", "remote"]

    try:
        if system == "Windows":
            r = subprocess.run(
                ["wmic", "path", "win32_videocontroller", "get", "name"],
                capture_output=True, text=True, check=False, timeout=5)
            for line in r.stdout.splitlines():
                line = line.strip().lower()
                if line and not any(x in line for x in skip):
                    if any(b in line for b in brands):
                        return True

        elif system == "Linux":
            r = subprocess.run(
                ["lspci"], capture_output=True, text=True, check=False, timeout=5)
            for line in r.stdout.splitlines():
                low = line.lower()
                if any(kw in low for kw in ["vga", "3d", "display"]):
                    if any(b in low for b in brands):
                        return True
    except Exception:
        pass

    return False


def get_gpu_name() -> str | None:
    system = platform.system()
    try:
        if system == "Windows":
            r = subprocess.run(
                ["wmic", "path", "win32_videocontroller", "get", "name"],
                capture_output=True, text=True, check=False, timeout=5)
            for line in r.stdout.splitlines():
                line = line.strip()
                if line and "name" not in line.lower():
                    if not any(x in line.lower() for x in ["intel", "microsoft",
                                                           "basic", "vmware"]):
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
