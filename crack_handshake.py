import os
import re
import sys
import threading
import time
import datetime
import subprocess

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from prompt_toolkit import prompt
    from prompt_toolkit.completion import PathCompleter
    from prompt_toolkit.validation import Validator, ValidationError
    from prompt_toolkit.shortcuts import PromptSession
    from prompt_toolkit.history import InMemoryHistory
except ImportError:
    print("Required Python libraries (rich, prompt_toolkit) not found. Attempting to install them...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "rich", "prompt_toolkit"])
        print("Libraries installed successfully. Please restart the program.")
        sys.exit(0)
    except Exception as e:
        print(f"Failed to install required libraries: {e}")
        print("Please install them manually using: pip install rich prompt_toolkit")
        sys.exit(1)

console = Console()
ERROR_LOG_FILE = "error_log.txt"

def log_error(message: str, error: Exception = None):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_message = f"[{timestamp}] ERROR: {message}"
    if error:
        log_message += f" - Exception: {type(error).__name__}: {error}"
    
    with open(ERROR_LOG_FILE, "a") as f:
        f.write(log_message + "\n")
    colored_log("error", f"An error occurred. Details logged to {ERROR_LOG_FILE}")
    if error:
        console.print_exception(show_locals=False)

def colored_log(level: str, message: str):
    if level == "info":
        console.print(f"[bold blue]INFO:[/bold blue] {message}", style="bold blue")
    elif level == "success":
        console.print(f"[bold green]SUCCESS:[/bold green] {message}", style="bold green")
    elif level == "warning":
        console.print(f"[bold yellow]WARNING:[/bold yellow] {message}", style="bold yellow")
    elif level == "error":
        console.print(f"[bold red]ERROR:[/bold red] {message}", style="bold red")
    else:
        console.print(message, style="white on red")

def execute_command(command: list[str]) -> "subprocess.CompletedProcess | None":
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False, encoding='utf-8', errors='replace')
        if result.returncode != 0:
            error_msg = f"Command failed with exit code {result.returncode}: {' '.join(command)}\nStdout: {result.stdout}\nStderr: {result.stderr}"
            log_error(f"Command execution error: {error_msg}")
        return result
    except FileNotFoundError:
        log_error(f"Command not found: '{command[0]}'. Make sure it's installed and in your PATH.")
        return None
    except Exception as e:
        log_error(f"Unhandled exception during command execution: {' '.join(command)}", e)
        return None

def check_dependency(tool_name: str) -> bool:
    try:
        result = execute_command(["which", tool_name])
        if result and result.returncode == 0:
            colored_log("success", f"{tool_name} found!")
            return True
        colored_log("error", f"{tool_name} is not installed or not in your PATH.")
        colored_log("info", f"Please install {tool_name} (e.g., [bold cyan]sudo apt-get install {tool_name}[/bold cyan] on Debian/Ubuntu).")
        return False
    except Exception as e:
        log_error(f"Error checking dependency for {tool_name}", e)
        colored_log("error", f"Could not check dependency for {tool_name} due to an error.")
        return False

def sanitize_ssid(ssid: str) -> str:
    return re.sub(r'[\\/*?:"<>|]', "", ssid).replace(" ", "_").strip()

def _check_handshake(cap_file: str) -> bool:
    if not os.path.exists(cap_file):
        colored_log("error", f"Handshake file not found: {cap_file}. Please check the path.")
        return False
    colored_log("info", f"Validating handshake in: [bold yellow]{os.path.basename(cap_file)}[/bold yellow]...")
    
    try:
        result = execute_command(["aircrack-ng", cap_file])
        if result and "1 handshake" in result.stdout:
            colored_log("success", "Handshake validation successful: At least one 4-way handshake found!")
            return True
        else:
            colored_log("warning", "No valid 4-way handshake detected in this file.")
            colored_log("info", "Please ensure the .cap/.pcap file contains a full WPA/WPA2 4-way handshake.")
            if result and result.stderr:
                console.print(f"[dim]Aircrack-ng output (stderr):[/dim]\n[dim]{result.stderr}[/dim]", style="dim")
            return False
    except Exception as e:
        log_error(f"Error during handshake validation for {cap_file}", e)
        colored_log("error", "Failed to validate handshake due to an internal error.")
        return False

def crack_password_from_handshake(handshake_path: str, wordlist_path: str) -> str | None:
    colored_log("info", f"Using wordlist: [bold green]{os.path.basename(wordlist_path)}[/bold green]")
    try:
        with Progress(
            SpinnerColumn("dots", style="bold magenta"),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
            console=console
        ) as progress:
            cracking_task = progress.add_task("[bold yellow]Cracking in progress[/bold yellow]...", total=None)

            start_time = time.time()
            result = execute_command(["aircrack-ng", "-w", wordlist_path, handshake_path])

            progress.remove_task(cracking_task)

        if not result or result.returncode != 0 and "KEY FOUND!" not in result.stdout:
            colored_log("error", "Aircrack-ng command failed or did not find a key.")
            if result and result.stderr:
                console.print(f"[dim]Aircrack-ng error output:[/dim]\n[dim]{result.stderr}[/dim]", style="dim")
            return None

        if "KEY FOUND!" in result.stdout:
            match = re.search(r"KEY FOUND!\s*\[\s*(.*?)\s*\]", result.stdout)
            if match:
                password = match.group(1)
                elapsed_time = time.time() - start_time
                minutes, seconds = divmod(int(elapsed_time), 60)
                time_str = f"{minutes:02d}:{seconds:02d}"

                essid_match = re.search(r"SSID:\s*(.*)", result.stdout)
                network_essid = essid_match.group(1).strip() if essid_match else os.path.basename(handshake_path).replace(".cap", "").replace(".pcap", "")

                console.print("\n" + "[bold green]Password Found![/bold green] 🎉")
                console.print(f"  [bold cyan]Network Name:[/bold cyan] [bold yellow]{network_essid}[/bold yellow]")
                console.print(f"  [bold green]Password:[/bold green] [bold green]{password}[/bold green]") # Changed password to green, not highlighted
                console.print(f"  [bold blue]Time Taken:[/bold blue] {time_str}")
                
                results_dir = "cracked_results"
                os.makedirs(results_dir, exist_ok=True)
                safe_essid = sanitize_ssid(network_essid)
                result_file = os.path.join(results_dir, f"{safe_essid}_cracked_password.txt")
                with open(result_file, "w") as f:
                    f.write(f"Network (ESSID): {network_essid}\n")
                    f.write(f"Handshake File: {os.path.basename(handshake_path)}\n")
                    f.write(f"Wordlist Used: {os.path.basename(wordlist_path)}\n")
                    f.write(f"Password Found: {password}\n")
                    f.write(f"Time Taken: {time_str}\n")
                colored_log("info", f"Results saved to: [bold underline cyan]{result_file}[/bold underline cyan]")
                return password
        else:
            colored_log("error", "Password not found in the wordlist. Consider trying a different or larger wordlist!")
            if result:
                console.print(f"[dim]Aircrack-ng raw output (for debugging):[/dim]\n[dim]{result.stdout}[/dim]", style="dim")
            return None
    except Exception as e:
        log_error(f"Critical error during cracking process for {handshake_path}", e)
        colored_log("error", "Cracking process terminated due to an unexpected error.")
        return None

class PcapValidator(Validator):
    def validate(self, document):
        text = document.text
        if text.lower() in ['exit', 'q']:
            return
        if not os.path.exists(text):
            raise ValidationError(
                message="File not found!",
                cursor_position=len(text)
            )
        if not (text.lower().endswith(".cap") or text.lower().endswith(".pcap")):
            raise ValidationError(
                message="Not a .cap or .pcap file!",
                cursor_position=len(text)
            )

def main():
    try:
        console.print(Panel(
            Text("✨ Wi-Fi Handshake Cracker ✨", justify="center", style="bold magenta"),
            subtitle="Crack your own WPA/WPA2 handshakes",
            border_style="purple",
            padding=(1, 4)
        ))
        
        # Simpler welcome/instruction messages and ensuring color for Ctrl+C
        console.print(Text("\nTest your Wi-Fi security by cracking captured handshakes. Use responsibly and with permission.", style="bold blue").wrap(console, width=console.width - 4))
        console.print(Text.from_markup("Press [bold red]Ctrl+C[/bold red] to gracefully exit.", style="bold magenta")) # Fixed Ctrl+C rendering
        console.print("-" * console.width, style="dim")

        if not check_dependency("aircrack-ng"):
            colored_log("error", "Dependency check failed. Please install 'aircrack-ng' to proceed.")
            sys.exit(1)

        session = PromptSession(history=InMemoryHistory())

        handshake_file_path = ""
        while True:
            try:
                console.print("\n[bold cyan]Enter the full path to your handshake capture file (.cap/.pcap):[/bold cyan]")
                console.print("[dim]  (Type 'exit'/'q' to quit. Use TAB for auto-completion.)[/dim]")
                
                handshake_file_path = session.prompt(
                    "Path: ",
                    completer=PathCompleter(only_directories=False, expanduser=True),
                    validator=PcapValidator(),
                    validate_while_typing=True
                ).strip()

                if handshake_file_path.lower() in ['exit', 'q']:
                    colored_log("info", "Exiting program as requested.")
                    sys.exit(0)
                
                if os.path.exists(handshake_file_path) and \
                   (handshake_file_path.lower().endswith(".cap") or handshake_file_path.lower().endswith(".pcap")):
                    break
                else:
                    colored_log("error", "Invalid file path or format. Please ensure the file exists and is a .cap/.pcap file.")
            except ValidationError as e:
                colored_log("error", str(e))
            except EOFError:
                colored_log("info", "Exiting program.")
                sys.exit(0)
            except Exception as e:
                log_error("Error during handshake file input.", e)
                colored_log("error", "An error occurred during file path input. Please try again or restart.")
                time.sleep(1)

        wordlist_name = "wifite.txt"
        wordlist_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), wordlist_name)

        if not os.path.exists(wordlist_path):
            colored_log("error", f"Wordlist '[bold yellow]{wordlist_name}[/bold yellow]' not found in the same directory as this script.")
            colored_log("info", "Please create or place a valid wordlist file named 'wifite.txt' here.")
            sys.exit(1)
        else:
            colored_log("info", f"Using wordlist: [bold green]{os.path.basename(wordlist_path)}[/bold green]")

        if not _check_handshake(handshake_file_path):
            colored_log("error", "Handshake validation failed. Cracking process aborted.")
            sys.exit(1)

        colored_log("info", "Initiating password cracking. This might take a while depending on your wordlist and hardware.")
        cracked_password = crack_password_from_handshake(handshake_file_path, wordlist_path)

        if cracked_password:
            colored_log("success", "Cracking process finished successfully!")
        else:
            console.print("\n" + "[bold red]Cracking Failed![/bold red] ❌")
            console.print(Text("Password was not found in the provided wordlist.", style="yellow"))
            colored_log("info", "Consider trying with a different or larger wordlist next time for better chances.")

    except KeyboardInterrupt:
        colored_log("warning", "\nProgram interrupted by user (Ctrl+C). Exiting gracefully.")
        sys.exit(1)
    except Exception as e:
        log_error("A critical unhandled error occurred in main execution.", e)
        colored_log("error", "A critical error occurred. Check 'error_log.txt' for details. Exiting.")
        sys.exit(1)

if __name__ == "__main__":
    main()
