import datetime
import sys
import os
import tempfile

from rich.console import Console


def _enable_vt():
    try:
        if sys.platform == "win32":
            import ctypes
            kernel32 = ctypes.windll.kernel32
            hStdout = kernel32.GetStdHandle(-11)
            mode = ctypes.c_uint32()
            if kernel32.GetConsoleMode(hStdout, ctypes.byref(mode)):
                mode.value |= 0x0004
                kernel32.SetConsoleMode(hStdout, mode)
                return True
    except Exception:
        pass
    return False


def _init_colorama():
    try:
        import colorama
        colorama.init()
        return True
    except Exception:
        return False


_enable_vt()
_init_colorama()

console = Console(highlight=False)
_error_log_file = None


def _get_error_log():
    global _error_log_file
    if _error_log_file is not None:
        return _error_log_file
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    name = f"error_log_{timestamp}.txt"
    for base in [os.getcwd(), tempfile.gettempdir()]:
        try:
            path = os.path.join(base, name)
            with open(path, "a"):
                pass
            _error_log_file = path
            return path
        except (OSError, PermissionError):
            continue
    _error_log_file = os.path.join(tempfile.gettempdir(), name)
    return _error_log_file


def colored_log(level: str, message: str):
    markers = {"info": " *", "success": " +", "warning": " !", "error": " -"}
    prefix = markers.get(level, "  ")
    console.print(f"{prefix} {message}")


def log_error(message: str, error: Exception = None):
    error_log = _get_error_log()
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_message = f"[{timestamp}] ERROR: {message}"
    if error:
        log_message += f" - Exception: {type(error).__name__}: {error}"
    with open(error_log, "a") as f:
        f.write(log_message + "\n")
    if error:
        colored_log("error", f"An error occurred. Details logged to {error_log}")
        console.print_exception(show_locals=False)
