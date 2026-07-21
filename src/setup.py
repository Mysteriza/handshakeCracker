import os
import subprocess

from rich.panel import Panel
from rich.text import Text

from src.console import console, colored_log, log_error
from src.config import HANDSHAKES_DIR, RESULTS_DIR, WORDLIST_NAME, WORDLIST_URL
from src.utils import download_wordlist


def check_dependency(tool_name: str) -> bool:
    try:
        result = subprocess.run(
            ["which", tool_name],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode == 0:
            return True
        colored_log("error", f"{tool_name} is not installed or not in your PATH.")
        colored_log("info", f"Install it with: sudo apt-get install {tool_name}")
        return False
    except Exception as e:
        log_error(f"Error checking dependency for {tool_name}", e)
        colored_log("error", f"Could not check dependency for {tool_name} due to an error.")
        return False


def show_banner():
    console.print(
        Panel(
            Text("Wi-Fi Handshake Cracker", justify="center"),
            subtitle="Audit your WPA/WPA2 handshakes",
            border_style="blue",
            padding=(1, 4),
        )
    )
    console.print("\n[cyan]Initializing...[/cyan]")


def ensure_directories() -> bool:
    os.makedirs(RESULTS_DIR, exist_ok=True)

    if not os.path.exists(HANDSHAKES_DIR):
        os.makedirs(HANDSHAKES_DIR)
        console.print(
            f"\n[yellow]Directory '{HANDSHAKES_DIR}' has been created.[/yellow]"
        )
        console.print(
            f"Please place your .cap/.pcap handshake files inside "
            f"the '{HANDSHAKES_DIR}' folder."
        )
        console.print("Then re-run this program.\n")
        input("Press Enter after you have added handshake files...")
        if not os.listdir(HANDSHAKES_DIR):
            colored_log("warning", "No files found in handshakes directory.")
            return False

    return True


def ensure_wordlist() -> bool:
    wordlist_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", WORDLIST_NAME
    )
    if os.path.exists(wordlist_path):
        return True

    colored_log("warning", f"Wordlist '{WORDLIST_NAME}' not found.")
    console.print("The program can download it automatically from GitHub.")
    choice = input("Download wordlist? (Y/n): ").strip().lower()
    if choice == "n":
        colored_log(
            "error",
            f"Wordlist '{WORDLIST_NAME}' is required. "
            f"Please place it in the program directory.",
        )
        return False

    if download_wordlist(WORDLIST_URL, wordlist_path):
        colored_log("success", "Wordlist ready.")
        return True

    return False


def auto_setup() -> bool:
    show_banner()
    if not check_dependency("aircrack-ng"):
        colored_log("error", "aircrack-ng is required. Install it then re-run the program.")
        return False
    if not ensure_directories():
        return False
    if not ensure_wordlist():
        return False
    return True
