# ✨ Wi-Fi Handshake Cracker ✨

## Overview
A powerful, user-friendly Python command-line tool designed for auditing Wi-Fi network security by cracking pre-captured WPA/WPA2 handshakes. It prioritizes efficiency, effective processing, and clear information delivery, making security testing intuitive and accessible.

## Features
* **Crack Existing Handshakes**: Capable of cracking pre-captured Wi-Fi handshake files in both `.cap` and `.pcap` formats.
* **Flexible Input Modes**: Choose between automatically scanning a default `handshakes/` directory for .cap/.pcap files or manually entering paths one by one.
* **Queued Processing**: Efficiently processes multiple handshake files one after another, ideal for batch cracking tasks.
* **Duplicate Skipping**: Automatically skips cracking attempts for networks (identified by ESSID) that have already been processed (successfully or unsuccessfully) in previous runs or within the current session, preventing redundant work.
* **Smart Prioritization**: Sorts the cracking queue by file size (largest files first) to prioritize potentially more robust or valuable handshakes.
* **Automatic Dependency Installation**: Intelligently checks for and automatically installs required Python libraries (`rich` and `prompt_toolkit`) if they are not already present in your environment.
* **Interactive CLI**: Utilizes `prompt_toolkit` for an intuitive command-line interface, offering real-time path validation and tab-completion for easy file selection.
* **Enhanced Cracking Animation**: Features a dynamic and visually appealing cracking animation in the terminal, providing real-time status updates for the currently processed handshake without cluttering the output.
* **Clean & Informative Output**: Suppresses verbose Aircrack-ng debug output from the terminal, logging it to a timestamped file (`error_log_YYYYMMDD_HHMMSS.txt`) instead. Displays key information like detected Network ESSID during processing.
* **Robust Error Handling**: Designed to gracefully handle various potential errors, logging detailed error information for debugging.
* **Graceful Exit**: Allows for a clean program termination by pressing `Ctrl+C` at any point.
* **Password Highlighting**: Successfully cracked passwords are clearly highlighted in the output for immediate visibility and saved to dedicated result files.

## Screenshot
![Screenshot 2025-06-27 211249](https://github.com/user-attachments/assets/eacda6e2-b307-42dc-9601-76fb768b051e)

## Prerequisites

Before running this program, ensure you have the following installed:

* **Operating System**: Kali Linux (recommended) or any other Debian/Ubuntu-based Linux distribution. This tool heavily relies on Linux-specific utilities.
* **Aircrack-ng**: The core utility for cracking.
    ```bash
    sudo apt update
    sudo apt install aircrack-ng -y
    ```
* **Python 3**: Python 3 and the `python3-venv` module are required.
    ```bash
    sudo apt install python3 python3-venv -y
    ```

## Installation

Follow these steps in your Linux terminal to set up the project:

1.  **Clone the Repository**:
    ```bash
    git clone [https://github.com/Mysteriza/handshakeCracker](https://github.com/Mysteriza/handshakeCracker) # Replace with your repo URL
    ```

2.  **Navigate to your Project Directory**:
    ```bash
    cd handshakeCracker
    ```

3.  **Create a Virtual Environment**:
    This isolates the project's Python dependencies.
    ```bash
    python3 -m venv venv
    ```

4.  **Activate the Virtual Environment**:
    You will see `(venv)` appear at the beginning of your terminal prompt.
    ```bash
    source venv/bin/activate
    ```

5.  **Install Python Dependencies**:
    The program will attempt to auto-install `rich` and `prompt_toolkit` on first run if missing. However, you can also manually ensure they are installed within your active `venv`:
    ```bash
    pip install rich prompt_toolkit
    ```
    *(Note: If you have a `requirements.txt` file, you can also use `pip install -r requirements.txt` if it contains `rich` and `prompt_toolkit`.)*

## Usage

1.  **Run the Program**:
    Ensure you are in the project directory and your virtual environment is active (`(venv)` is visible in your prompt).
    ```bash
    python crack_handshake.py
    ```

2.  **Follow the Prompts**:
    The program will guide you through the process:
    * **Choose Input Mode**:
        * Enter `0` for **Auto** to scan the `handshakes/` directory for all `.cap/.pcap` files.
        * Enter `1` for **Manual** to input handshake file paths one by one.
        * Enter `3` to **Exit** the program.
    * **Enter Handshake Paths (Manual Mode)**: If you selected Manual mode, you will be prompted to enter handshake file paths one by one. Use `TAB` for auto-completion. Type `done` or `q` when you have finished adding files.
    * The program will then process the handshakes in the queue, displaying progress and results.

## Important: Responsible Use!
This tool is designed purely for security testing and educational purposes. **Always use this tool ethically and only on Wi-Fi networks that you own or for which you have explicit, written permission to test.** Unauthorized use on other networks is illegal and unethical.
