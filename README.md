# ✨ Wi-Fi Handshake Cracker ✨

## Overview
A simple, robust, and user-friendly Python tool designed for auditing Wi-Fi network security by cracking pre-captured WPA/WPA2 handshakes. It focuses on efficiency, effectiveness, and clear information delivery, making security testing accessible and intuitive.

## Features
* **Crack Existing Handshakes**: Capable of cracking pre-captured Wi-Fi handshake files in both `.cap` and `.pcap` formats.
* **Automatic Dependency Installation**: Intelligently checks for and automatically installs required Python libraries (`rich` and `prompt_toolkit`) if they are not already present in your environment.
* **Interactive CLI**: Utilizes `prompt_toolkit` for an intuitive command-line interface, offering real-time path validation and tab-completion for easy file selection.
* **Robust Error Handling**: Designed to gracefully handle various potential errors, logging detailed error information to `error_log.txt` for easy debugging.
* **Graceful Exit**: Allows for a clean program termination by pressing `Ctrl+C` at any point.
* **Vibrant Console Output**: Features clear, concise, and colorful terminal output powered by the `rich` library, ensuring an easy-to-read and engaging user experience.
* **Password Highlighting**: Successfully cracked passwords are clearly highlighted in the output for immediate visibility.

## Prerequisites

Before running this program, ensure you have the following installed (the program will automatically install all dependencies anyway):

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

1.  **Navigate to your Project Directory**:
    If you've just downloaded the files, navigate to the `handshakeCracker` folder:
    ```bash
    cd handshakeCracker
    ```

2.  **Create a Virtual Environment**:
    This isolates the project's Python dependencies.
    ```bash
    python3 -m venv venv
    ```

3.  **Activate the Virtual Environment**:
    You will see `(venv)` appear at the beginning of your terminal prompt.
    ```bash
    source venv/bin/activate
    ```

4.  **Install Python Dependencies**:
    The program will attempt to auto-install `rich` and `prompt_toolkit` on first run if missing. However, you can also manually ensure they are installed within your active `venv`:
    ```bash
    pip install rich prompt_toolkit
    ```
    *(Note: If you have a `requirements.txt` file, you can also use `pip install -r requirements.txt`.)*

## Usage

1.  **Prepare Your Wordlist**:
    The program expects a file named `wifite.txt` in the same directory as `crack_handshake.py`. This file should contain a list of potential passwords, one password per line.
    Example `wifite.txt` content:
    ```
    password123
    qwerty
    12345678
    myhomewifi
    ```

2.  **Run the Program**:
    Ensure you are in the project directory and your virtual environment is active (`(venv)` is visible in your prompt).
    ```bash
    python crack_handshake.py
    ```

3.  **Follow the Prompts**:
    The program will ask you to enter the full path to your handshake capture file (`.cap` or `.pcap`).
    * You can use the `TAB` key for auto-completion.
    * You can type `exit` or `q` at any time to quit the program.
    If a password is found, it will be displayed in the console and saved to a text file within the `cracked_results` folder.

## Important: Responsible Use!
This tool is designed purely for security testing and educational purposes. **Always use this tool ethically and only on Wi-Fi networks that you own or for which you have explicit, written permission to test.** Unauthorized use on other networks is illegal and unethical.

---
