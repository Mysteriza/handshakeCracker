import sys
import os
import tempfile
import logging

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

_logger = logging.getLogger("handshakeCracker")
_logger.setLevel(logging.DEBUG)


def _get_log_dir() -> str:
    base = os.path.join(os.getcwd(), "logs")
    try:
        os.makedirs(base, exist_ok=True)
        test_path = os.path.join(base, ".write_test")
        with open(test_path, "w") as f:
            f.write("test")
        os.remove(test_path)
        return base
    except (OSError, PermissionError):
        temp_dir = os.path.join(tempfile.gettempdir(), "handshakeCracker_logs")
        os.makedirs(temp_dir, exist_ok=True)
        return temp_dir


def _cleanup_old_logs(log_dir: str, max_logs: int = 10):
    """Keep only the latest `max_logs` debug_log files in `log_dir`."""
    try:
        import glob
        logs = glob.glob(os.path.join(log_dir, "debug_log_*.txt"))
        logs.sort(key=os.path.getmtime, reverse=True)
        # Delete logs that exceed the maximum minus one (since we are about to create a new one)
        for old_log in logs[max_logs - 1:]:
            try:
                os.remove(old_log)
            except OSError:
                pass
    except Exception:
        pass


from datetime import datetime

_log_dir = _get_log_dir()
_cleanup_old_logs(_log_dir, max_logs=10)
_log_file = os.path.join(_log_dir, f"debug_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")

_handler = logging.FileHandler(_log_file, encoding='utf-8')
_formatter = logging.Formatter("[%(asctime)s] %(levelname)s: %(message)s", "%Y-%m-%d %H:%M:%S")
_handler.setFormatter(_formatter)
_logger.addHandler(_handler)


def colored_log(level: str, message: str):
    markers = {"info": " *", "success": " +", "warning": " !", "error": " -"}
    prefix = markers.get(level, "  ")
    console.print(f"{prefix} {message}")


def log_debug(message: str, data=None):
    if data is not None:
        _logger.debug(f"{message} - {data}")
    else:
        _logger.debug(message)


def log_error(message: str, error: Exception | None = None):
    if error:
        _logger.error(f"{message} - Exception: {type(error).__name__}: {error}")
        colored_log("error", f"An error occurred. Details logged to {_log_file}")
    else:
        _logger.error(message)
