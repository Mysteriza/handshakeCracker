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
    base = os.getcwd()
    try:
        test_path = os.path.join(base, "debug_log.txt")
        with open(test_path, "a"):
            pass
        return base
    except (OSError, PermissionError):
        return tempfile.gettempdir()


from datetime import datetime

_log_file = os.path.join(_get_log_dir(), f"debug_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")

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
