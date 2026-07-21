import datetime
from rich.console import Console

console = Console()
_error_log_file = None


def _get_error_log():
    global _error_log_file
    if _error_log_file is None:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        _error_log_file = f"error_log_{timestamp}.txt"
    return _error_log_file


def colored_log(level: str, message: str):
    if level == "info":
        console.print(f"[cyan]{message}[/cyan]")
    elif level == "success":
        console.print(f"[green]{message}[/green]")
    elif level == "warning":
        console.print(f"[yellow]{message}[/yellow]")
    elif level == "error":
        console.print(f"[red]{message}[/red]")
    else:
        console.print(message)


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
