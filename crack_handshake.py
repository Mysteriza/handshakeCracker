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
# Generate timestamped error log filename once at startup
def get_error_log_filename():
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"error_log_{timestamp}.txt"

ERROR_LOG_FILE = get_error_log_filename()

def log_error(message: str, error: Exception = None):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_message = f"[{timestamp}] ERROR: {message}"
    if error:
        log_message += f" - Exception: {type(error).__name__}: {error}"
    
    with open(ERROR_LOG_FILE, "a") as f:
        f.write(log_message + "\n")
    if error: # Only print general error message to console if it's a code-level exception
        colored_log("error", f"An error occurred. Details logged to {ERROR_LOG_FILE}")
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

# New function: get_already_cracked_essids
def get_already_cracked_essids(results_dir="cracked_results") -> set[str]:
    """
    Scans the results directory for already cracked ESSIDs based on filenames.
    Returns a set of sanitized ESSIDs found in result files.
    """
    cracked_essids = set()
    if not os.path.exists(results_dir):
        return cracked_essids # Return empty set if directory doesn't exist
    
    try:
        for filename in os.listdir(results_dir):
            if filename.endswith("_cracked_password.txt"):
                # Extract ESSID from filename (e.g., "ESSID_cracked_password.txt")
                # The ESSID in the filename is already sanitized
                essid_part = filename.replace("_cracked_password.txt", "")
                cracked_essids.add(essid_part)
    except Exception as e:
        log_error(f"Error scanning results directory {results_dir} for cracked ESSIDs.", e)
    
    return cracked_essids

def get_essid_from_file_analysis(cap_file: str) -> str:
    """Attempts to extract ESSID from a .cap file's aircrack-ng analysis output for display."""
    essid = os.path.basename(cap_file).replace(".cap", "").replace(".pcap", "") # Default to filename
    try:
        result = execute_command(["aircrack-ng", cap_file])
        if result and result.stdout:
            # Pattern to match "BSSID ESSID Encryption" line in summary
            # Example: "DA:97:8D:FB:3E:BD   Hmmmmmmmm        WPA (1 handshake)"
            essid_line_match = re.search(r"[\dA-Fa-f:]{17}\s*(.*?)\s+(?:WEP|WPA)", result.stdout)
            if essid_line_match:
                found_essid = essid_line_match.group(1).strip()
                if found_essid != "" and found_essid != "<hidden>":
                    return found_essid
            
            # Fallback to general ESSID pattern (e.g., from Summary section)
            essid_match_summary = re.search(r"ESSID:\s*(.*?)(?:\s*\([\dA-Fa-f:]{17}\))?", result.stdout)
            if essid_match_summary:
                found_essid_summary = essid_match_summary.group(1).strip()
                if found_essid_summary != "" and found_essid_summary != "<hidden>":
                    return found_essid_summary
            
            if "ESSID: <hidden>" in result.stdout:
                return "<hidden>"

    except Exception as e:
        log_error(f"Error extracting ESSID for display from {cap_file}", e)
    
    return essid # Return default (filename-based) if nothing found

def _check_handshake(cap_file: str) -> bool:
    if not os.path.exists(cap_file):
        colored_log("error", f"Handshake file not found: {cap_file}. Please check the path.")
        return False
    try:
        result = execute_command(["aircrack-ng", cap_file])
        if result and "1 handshake" in result.stdout:
            return True
        else:
            colored_log("error", f"No valid 4-way handshake detected in [bold yellow]{os.path.basename(cap_file)}[/bold yellow].")
            colored_log("info", "Please ensure the .cap/.pcap file contains a full WPA/WPA2 4-way handshake.")
            if result and result.stderr:
                log_error(f"Aircrack-ng validation output for {os.path.basename(cap_file)}:\n{result.stderr}")
            return False
    except Exception as e:
        log_error(f"Error during handshake validation for {cap_file}", e)
        colored_log("error", "Failed to validate handshake due to an internal error.")
        return False

def parse_aircrack_failure_summary(output: str) -> dict:
    """Parses aircrack-ng's raw output to extract key summary details on failure."""
    parsed_info = {
        "keys_tested": "N/A",
        "time_left": "N/A",
        "percentage": "N/A",
        "current_passphrase": "N/A",
        "master_key": "N/A",
        "transient_key": "N/A",
        "eapol_hmac": "N/A"
    }

    lines = output.splitlines()
    for i in range(len(lines) - 1, -1, -1):
        line = lines[i]

        if "keys tested" in line and parsed_info["keys_tested"] == "N/A":
            match = re.search(r"(\d+)/(\d+)\s+keys tested\s+\(([\d.]+ k/s)\)", line)
            if match:
                parsed_info["keys_tested"] = f"{match.group(1)}/{match.group(2)} keys tested ({match.group(3)})"
            if i + 1 < len(lines):
                time_percent_line = lines[i+1]
                time_match = re.search(r"Time left:\s*(.*?)\s*([\d.]+\%)", time_percent_line)
                if time_match:
                    parsed_info["time_left"] = time_match.group(1).strip()
                    parsed_info["percentage"] = time_match.group(2).strip()
            continue

        if "Current passphrase:" in line and parsed_info["current_passphrase"] == "N/A":
            match = re.search(r"Current passphrase:\s*(.*)", line)
            if match:
                parsed_info["current_passphrase"] = match.group(1).strip()
            continue

        if "Master Key" in line and parsed_info["master_key"] == "N/A":
            match = re.search(r"Master Key\s*:\s*(.*)", line)
            if match:
                key_hex = match.group(1).strip()
                collected_key = [key_hex]
                for j in range(i + 1, len(lines)):
                    next_line = lines[j].strip()
                    if re.match(r"([\dA-Fa-f]{2}(?:\s[\dA-Fa-f]{2})*){1,16}", next_line):
                        collected_key.append(next_line)
                    else:
                        break
                parsed_info["master_key"] = "\n    ".join(collected_key)
            continue

        if "Transient Key" in line and parsed_info["transient_key"] == "N/A":
            match = re.search(r"Transient Key\s*:\s*(.*)", line)
            if match:
                key_hex = match.group(1).strip()
                collected_key = [key_hex]
                for j in range(i + 1, len(lines)):
                    next_line = lines[j].strip()
                    if re.match(r"([\dA-Fa-f]{2}(?:\s[\dA-Fa-f]{2})*){1,16}", next_line):
                        collected_key.append(next_line)
                    else:
                        break
                parsed_info["transient_key"] = "\n    ".join(collected_key)
            continue

        if "EAPOL HMAC" in line and parsed_info["eapol_hmac"] == "N/A":
            match = re.search(r"EAPOL HMAC\s*:\s*(.*)", line)
            if match:
                parsed_info["eapol_hmac"] = match.group(1).strip()
            continue
    
    return parsed_info

def crack_password_from_handshake(handshake_path: str, wordlist_path: str, display_essid: str) -> str | None:
    colored_log("info", f"Using wordlist: [bold green]{os.path.basename(wordlist_path)}[/bold green]")
    
    result_stdout = ""
    result_stderr = ""

    try:
        progress_messages = [
            f"Cracking {display_essid}... Analyzing handshake data...",
            f"Processing {display_essid}... Searching for the key..."
        ]
        
        current_message_index = 0
        
        with Progress(
            SpinnerColumn("dots", style="bold magenta"),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
            console=console
        ) as progress:
            cracking_task = progress.add_task(f"[bold yellow]{progress_messages[current_message_index]}[/bold yellow]", total=None)

            start_time = time.time()
            last_message_update_time = start_time

            proc = subprocess.Popen(
                ["aircrack-ng", "-w", wordlist_path, handshake_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding='utf-8',
                errors='replace'
            )
            
            full_stdout = []
            full_stderr = []
            
            while True:
                line = proc.stdout.readline()
                if line:
                    full_stdout.append(line)
                    if "KEY FOUND!" in line:
                        break 

                current_time = time.time()
                if current_time - last_message_update_time >= 2:
                    current_message_index = (current_message_index + 1) % len(progress_messages)
                    progress.update(cracking_task, description=f"[bold yellow]{progress_messages[current_message_index]}[/bold yellow]")
                    last_message_update_time = current_time

                if proc.poll() is not None:
                    break

                time.sleep(0.05)

            remaining_stdout, remaining_stderr = proc.communicate()
            full_stdout.append(remaining_stdout)
            full_stderr.append(remaining_stderr)

            result_stdout = "".join(full_stdout)
            result_stderr = "".join(full_stderr)

            progress.remove_task(cracking_task)

        if proc.returncode != 0 and "KEY FOUND!" not in result_stdout:
            colored_log("error", "Aircrack-ng command failed or did not find a key.")
            log_error(f"Aircrack-ng command failed for {os.path.basename(handshake_path)}:\nStdout:\n{result_stdout}\nStderr:\n{result_stderr}")
            return None

        if "KEY FOUND!" in result_stdout:
            match = re.search(r"KEY FOUND!\s*\[\s*(.*?)\s*\]", result_stdout)
            if match:
                password = match.group(1)
                elapsed_time = time.time() - start_time
                minutes, seconds = divmod(int(elapsed_time), 60)
                time_str = f"{minutes:02d}:{seconds:02d}"

                essid_match = re.search(r"SSID:\s*(.*)", result_stdout)
                final_network_essid = display_essid 
                
                if essid_match and essid_match.group(1).strip() != "" and essid_match.group(1).strip() != "<hidden>":
                     final_network_essid = essid_match.group(1).strip()
                elif final_network_essid == "<hidden>" or final_network_essid.endswith("_from_filename"): 
                     final_network_essid = os.path.basename(handshake_path).replace(".cap", "").replace(".pcap", "") + "_determined_final"
                

                console.print("\n" + "[bold green]Password Found![/bold green] 🎉")
                console.print(f"  [bold cyan]Network Name:[/bold cyan] [bold yellow]{final_network_essid}[/bold yellow]")
                console.print(f"  [bold green]Password:[/bold green] [bold green]{password}[/bold green]")
                console.print(f"  [bold blue]Time Taken:[/bold blue] {time_str}")
                
                results_dir = "cracked_results"
                os.makedirs(results_dir, exist_ok=True)
                sanitized_essid = sanitize_ssid(final_network_essid)
                result_file = os.path.join(results_dir, f"{sanitized_essid}_cracked_password.txt")
                with open(result_file, "w") as f:
                    f.write(f"Network (ESSID): {final_network_essid}\n")
                    f.write(f"Handshake File: {os.path.basename(handshake_path)}\n")
                    f.write(f"Wordlist Used: {os.path.basename(wordlist_path)}\n")
                    f.write(f"Password Found: {password}\n")
                    f.write(f"Time Taken: {time_str}\n")
                colored_log("info", f"Results saved to: [bold underline cyan]{result_file}[/bold underline cyan]")
                return password
        else:
            colored_log("error", "Password not found in the wordlist. Consider trying a different or larger wordlist!")
            return None
    except Exception as e:
        log_error(f"Critical error during cracking process for {handshake_path}", e)
        colored_log("error", "Cracking process terminated due to an unexpected error.")
        return None

class PcapValidator(Validator):
    def validate(self, document):
        text = document.text
        if text.lower() == 'q' or text.lower() == 'done':
            return
        
        if not os.path.exists(text):
            raise ValidationError(message=f"File not found: {text}", cursor_position=len(text))
        if not (text.lower().endswith(".cap") or text.lower().endswith(".pcap")):
            raise ValidationError(message=f"Not a .cap or .pcap file: {text}", cursor_position=len(text))

# New helper function to scan default directory
def scan_default_directory(directory_path: str) -> list[str]:
    found_files = []
    if not os.path.exists(directory_path):
        colored_log("error", f"Default directory [bold red]{directory_path}[/bold red] not found.")
        return []
    
    colored_log("info", f"Scanning directory: [bold yellow]{directory_path}[/bold yellow] for .cap/.pcap files...")
    for root, _, files in os.walk(directory_path):
        for file in files:
            if file.lower().endswith((".cap", ".pcap")):
                full_path = os.path.join(root, file)
                found_files.append(full_path)
    return found_files

# New helper function to encapsulate manual input
def get_manual_handshake_paths(session: PromptSession) -> list[str]:
    manual_queue = []
    console.print("\n[bold cyan]Please enter handshake file paths (.cap/.pcap) one by one.[/bold cyan]")
    console.print("[dim]  (Type 'done' or 'q' to finish adding files. Use TAB for auto-completion.)[/dim]")
    
    while True:
        try:
            current_input_path = session.prompt(
                f"Handshake {len(manual_queue) + 1} Path: ",
                completer=PathCompleter(only_directories=False, expanduser=True),
                validator=PcapValidator(),
                validate_while_typing=True
            ).strip()

            if current_input_path.lower() in ['done', 'q']:
                break 

            manual_queue.append(current_input_path)
            colored_log("info", f"Added: [bold yellow]{os.path.basename(current_input_path)}[/bold yellow] to queue.")
        
        except ValidationError as e:
            colored_log("error", str(e))
        except EOFError:
            colored_log("info", "Exiting program.")
            sys.exit(0)
        except Exception as e:
            log_error("Error during manual handshake file input.", e)
            colored_log("error", "An error occurred during file path input. Please try again or restart.")
            time.sleep(1)
    
    return manual_queue

def main():
    os.system('cls' if os.name == 'nt' else 'clear')

    try:
        console.print(Panel(
            Text("✨ Wi-Fi Handshake Cracker ✨", justify="center", style="bold magenta"),
            subtitle="Crack your own WPA/WPA2 handshakes",
            border_style="purple",
            padding=(1, 4)
        ))
        
        console.print(Text("\nTest your Wi-Fi security by cracking captured handshakes. Use responsibly and with permission.", style="bold blue").wrap(console, width=console.width - 4))
        console.print(Text.from_markup("Press [bold red]Ctrl+C[/bold red] to gracefully exit.", style="bold magenta"))
        console.print("-" * console.width, style="dim")

        if not check_dependency("aircrack-ng"):
            colored_log("error", "Dependency check failed. Please install 'aircrack-ng' to proceed.")
            sys.exit(1)

        session = PromptSession(history=InMemoryHistory())

        handshake_queue = []
        
        # Input mode choice
        def validate_input_mode_choice_value(text): 
            if text.lower() not in ['0', '1', '3']:
                raise ValidationError(message="Please enter '0', '1', or '3'.", cursor_position=len(text))

        input_mode_choice = ""
        while input_mode_choice not in ['0', '1', '3']:
            console.print("\n[bold cyan]Choose input mode:[/bold cyan]")
            console.print("[dim]  0. Auto (Use all .cap/.pcap files from 'handshakes' directory)[/dim]")
            console.print("[dim]  1. Manual (Enter custom path(s) one by one)[/dim]")
            console.print("[dim]  3. Exit program[/dim]")
            # Use standard input() for this simple choice, as per user's last request.
            input_mode_choice = input("Mode (0/1/3): ").strip().lower() 

            try:
                # Manually validate input from the raw input() function
                # No need to use Validator object directly for validation as input() handles it
                if input_mode_choice not in ['0', '1', '3']:
                    # Use the error message directly from the validation logic
                    colored_log("error", "Invalid input. Please enter '0', '1', or '3'.") 
                    input_mode_choice = "" # Reset to force loop continuation
            except Exception as e:
                log_error("An unexpected error occurred during mode selection validation.", e)
                colored_log("error", "An unexpected error occurred during mode selection validation. Check log for details.")
                input_mode_choice = ""


        if input_mode_choice == '3':
            colored_log("info", "Exiting program as requested.")
            sys.exit(0)

        if input_mode_choice == '1': # Manual mode
            handshake_queue = get_manual_handshake_paths(session)
        elif input_mode_choice == '0': # Auto mode
            default_handshakes_dir = "handshakes"
            found_files = scan_default_directory(default_handshakes_dir)
            if not found_files:
                colored_log("warning", f"No .cap/.pcap files found in [bold yellow]{default_handshakes_dir}[/bold yellow].")
                console.print("[dim]You can either create this directory and place files in it, or choose manual input.[/dim]")
                
                switch_to_manual = session.prompt(Text("Do you want to switch to [bold green]manual input[/bold green] (y/n)? ", style="bold yellow").markup, validator=Validator(lambda text: text.lower() in ['y', 'n'], error_message="Please enter 'y' or 'n'."), validate_while_typing=False).strip().lower()
                if switch_to_manual == 'y':
                    handshake_queue = get_manual_handshake_paths(session)
                else:
                    colored_log("info", "Exiting program as no files found and manual input declined.")
                    sys.exit(0)
            else:
                handshake_queue.extend(found_files)
                colored_log("success", f"Found {len(found_files)} .cap/.pcap files in [bold yellow]{default_handshakes_dir}[/bold yellow]. Added to queue.")
                # Removed printing each added file to keep terminal clean
                # for f_path in found_files:
                #    colored_log("info", f"  - Added: [bold yellow]{os.path.basename(f_path)}[/bold yellow]")


        if not handshake_queue:
            colored_log("warning", "No handshake files in queue. Exiting program.")
            sys.exit(0)
        
        colored_log("info", f"\nProcessing {len(handshake_queue)} handshakes in queue...")
        
        wordlist_name = "wifite.txt"
        wordlist_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), wordlist_name)

        if not os.path.exists(wordlist_path):
            colored_log("error", f"Wordlist '[bold yellow]{wordlist_name}[/bold yellow]' not found in the same directory as this script.")
            colored_log("info", "Please create or place a valid wordlist file named 'wifite.txt' here.")
            sys.exit(1)
        else:
            colored_log("info", f"Using wordlist: [bold green]{os.path.basename(wordlist_path)}[/bold green]")

        # Get already cracked ESSIDs at startup
        already_cracked_essids = get_already_cracked_essids()
        if already_cracked_essids:
            colored_log("info", f"Found {len(already_cracked_essids)} previously cracked network(s). These will be skipped if encountered again.")
        
        # Sort handshake queue by file size (largest to smallest)
        handshake_queue.sort(key=lambda p: os.path.getsize(p), reverse=True)
        colored_log("info", "Handshakes sorted by file size (largest first).")

        
        for i, handshake_path in enumerate(handshake_queue):
            console.print("\n" + "=" * console.width, style="bold blue")
            colored_log("info", f"Processing Handshake {i+1}/{len(handshake_queue)}: [bold cyan]{os.path.basename(handshake_path)}[/bold cyan]")
            
            current_displayed_essid = get_essid_from_file_analysis(handshake_path)
            
            # Check if already cracked
            sanitized_current_essid = sanitize_ssid(current_displayed_essid)
            if sanitized_current_essid in already_cracked_essids:
                colored_log("warning", f"  Network ESSID: [yellow]{current_displayed_essid}[/yellow] already processed. Skipping.")
                console.print("-" * console.width, style="dim")
                continue # Skip to next handshake
            
            if current_displayed_essid != os.path.basename(handshake_path).replace(".cap", "").replace(".pcap", ""):
                 colored_log("info", f"  Network ESSID: [bold yellow]{current_displayed_essid}[/bold yellow]")
            else:
                 colored_log("warning", f"  Network ESSID: [yellow]{current_displayed_essid} (Could not auto-detect)[/yellow]")
            
            if not _check_handshake(handshake_path):
                colored_log("error", f"Validation failed for [bold red]{os.path.basename(handshake_path)}[/bold red]. Skipping to next handshake.")
                console.print("-" * console.width, style="dim")
                continue

            colored_log("info", "Initiating password cracking. This might take a while depending on your wordlist and hardware.")
            cracked_password = crack_password_from_handshake(handshake_path, wordlist_path, current_displayed_essid)

            if cracked_password:
                colored_log("success", "Cracking process finished successfully for this handshake!")
                already_cracked_essids.add(sanitized_current_essid)
            else:
                colored_log("error", "Cracking process failed for this handshake.")
                already_cracked_essids.add(sanitized_current_essid) # Mark as processed (failed)
            
            console.print("-" * console.width, style="dim")

        colored_log("success", "\nAll handshakes in queue have been processed!")
        colored_log("info", "Program finished. Exiting.")

    except KeyboardInterrupt:
        colored_log("warning", "\nProgram interrupted by user (Ctrl+C). Exiting gracefully.")
        sys.exit(1)
    except Exception as e:
        log_error("A critical unhandled error occurred in main execution.", e)
        colored_log("error", "A critical error occurred. Check 'error_log.txt' for details. Exiting.")
        sys.exit(1)

if __name__ == "__main__":
    main()