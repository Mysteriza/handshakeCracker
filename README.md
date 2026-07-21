# Wi-Fi Handshake Cracker

Audit WPA/WPA2 networks by cracking pre-captured handshakes. Cross-platform (Windows + Linux), fully automatic setup.

## Features

- **Zero-config** — Auto-installs Python packages, downloads aircrack-ng (Windows), and fetches wordlist on first run
- **Cross-platform** — Windows auto-downloads aircrack-ng binary; Linux auto-installs via apt-get
- **EAPOL validation** — Scapy-based M1/M2/M3/M4 table rejects invalid captures before cracking
- **Batch processing** — Queue multiple .cap/.pcap files from `handshakes/`
- **Duplicate skip** — Skips networks already cracked in previous runs
- **Error logging** — All errors written to timestamped `error_log_*.txt`

## Prerequisites

- **Python 3.8+**
- Internet connection (first-run downloads)

## Installation

```bash
git clone https://github.com/Mysteriza/handshakeCracker
cd handshakeCracker
python main.py
```

The program auto-installs all dependencies on first run. No manual setup required.

## Usage

```bash
python main.py
```

1. Place .cap/.pcap files in `handshakes/`
2. Run the program
3. It auto-downloads aircrack-ng (Windows) or installs via apt (Linux), downloads the wordlist, validates handshakes with Scapy, and cracks them

## Project Structure

```
handshakeCracker/
├── main.py              # Entry point
├── requirements.txt     # Python dependencies
├── wifite.txt           # Auto-downloaded wordlist
├── handshakes/          # Place .cap/.pcap files here
├── cracked_results/     # Cracked passwords saved here
├── bin/                 # Auto-populated aircrack-ng (Windows)
└── src/
    ├── config.py        # URLs, paths, constants
    ├── console.py       # Terminal helpers + error logging
    ├── utils.py         # Download, extraction, utilities
    ├── validator.py     # Scapy handshake validation
    ├── cracker.py       # Aircrack-ng cracking logic
    └── setup.py         # OS detection, auto-setup
```

## Legal

For authorized security testing and education only. Unauthorized use is illegal.
