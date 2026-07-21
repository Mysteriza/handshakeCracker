# Wi-Fi Handshake Cracker

Audit WPA/WPA2 Wi-Fi security by cracking pre-captured handshakes. Fully automatic, modular, and beginner-friendly.

## Features

- **Modular design** — Clean src/ structure for easy maintenance and future development.
- **Auto-setup** — Automatically creates directories, checks dependencies, and downloads the wordlist.
- **EAPOL validation** — Uses Scapy to check for valid M1+M2 handshake before cracking (rejects invalid captures).
- **Real-time progress** — Shows keys tested count and percentage during cracking.
- **Duplicate skipping** — Skips networks already cracked in previous runs.
- **Queue processing** — Handles multiple .cap/.pcap files in batch.
- **Auto-download wordlist** — Fetches latest `wifite.txt` from GitHub if missing.
- **Error logging** — All errors saved to timestamped `error_log_*.txt`.

## Prerequisites

- **Linux** (Kali / Debian / Ubuntu recommended)
- **aircrack-ng**
  ```bash
  sudo apt update && sudo apt install aircrack-ng -y
  ```
- **Python 3.8+**
  ```bash
  sudo apt install python3 python3-venv -y
  ```

## Installation

```bash
git clone https://github.com/Mysteriza/handshakeCracker
cd handshakeCracker
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

The program auto-installs missing dependencies on first run if you skip `pip install`.

## Usage

```bash
python main.py
```

The program will:
1. Check for `aircrack-ng` and Python dependencies.
2. Create `handshakes/` and `cracked_results/` directories.
3. Download wordlist from GitHub if missing.
4. Scan `handshakes/` for .cap/.pcap files.
5. Validate each file (M1+M2 EAPOL check).
6. Crack only valid handshakes.

Place your .cap/.pcap files in the `handshakes/` folder and run.

## Project Structure

```
handshakeCracker/
├── main.py              # Entry point
├── requirements.txt     # Python dependencies
├── wifite.txt           # Password wordlist
├── handshakes/          # Place .cap/.pcap files here
├── cracked_results/     # Cracked passwords saved here
└── src/
    ├── config.py        # Constants (paths, URLs)
    ├── console.py       # Terminal output helpers
    ├── utils.py         # Utilities (commands, downloads)
    ├── validator.py     # Scapy handshake validation
    ├── cracker.py       # Aircrack-ng cracking logic
    └── setup.py         # Auto-setup & dependency check
```

## Responsible Use

This tool is for security testing and education only. **Always use on networks you own or have explicit permission to test.** Unauthorized use is illegal.
