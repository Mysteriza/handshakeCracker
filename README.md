# Wi-Fi Handshake Cracker — v1.0.0

Audit WPA/WPA2 networks by cracking pre-captured handshakes. Cross-platform (Windows + Linux), fully automatic setup.

## Features

- **GPU acceleration** — Auto-detects discrete GPU (NVIDIA/AMD) and cracks via hashcat (100-300k PMK/s); falls back to CPU aircrack-ng if no GPU found
- **Zero-config** — Auto-installs Python packages, downloads aircrack-ng/hashcat, and fetches wordlist on first run
- **Cross-platform** — Windows auto-downloads binaries; Linux auto-installs via apt-get
- **EAPOL validation** — Scapy-based M1/M2/M3/M4 table rejects invalid captures before cracking
- **Batch processing** — Queue multiple .cap/.pcap files from `handshakes/`
- **Duplicate skip** — Skips networks already cracked in previous runs
- **Dynamic parallelism** — CPU mode uses 50% of cores at BELOW_NORMAL priority
- **Error logging** — All errors written to timestamped `error_log_*.txt`
- **Permission resilient** — Falls back to `%TEMP%` automatically if the project directory isn't writable
- **Auto-update** — Checks GitHub for updates on startup and pulls latest code automatically

## Performance

| Method | Device | Speed (PMK/s) | 10M passwords |
|--------|--------|:------------:|:-------------:|
| CPU (aircrack-ng) | 4-core laptop | ~2,000 | ~83 minutes |
| CPU (aircrack-ng) | 16-core desktop | ~8,000 | ~21 minutes |
| GPU (hashcat) | RTX 3060 | ~300,000 | ~50 seconds |
| GPU (hashcat) | RTX 4090 | ~1,200,000 | ~12 seconds |

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
3. It auto-detects GPU → uses hashcat (with aircrack-ng fallback), validates handshakes with Scapy, and cracks them

## Project Structure

```
handshakeCracker/
├── main.py              # Entry point
├── requirements.txt     # Python dependencies
├── wifite.txt           # Auto-downloaded wordlist
├── handshakes/          # Place .cap/.pcap files here
├── cracked_results/     # Cracked passwords saved here
├── bin/                 # Auto-populated aircrack-ng + hashcat binaries
├── hc22000_cache/       # Temporary .hc22000 conversion cache
└── src/
    ├── config.py        # URLs, paths, constants
    ├── console.py       # Terminal helpers + error logging
    ├── utils.py         # Download, extraction, utilities
    ├── validator.py     # Scapy handshake validation
    ├── gpu.py           # Discrete GPU detection
    ├── cracker.py       # Aircrack-ng cracking (CPU fallback)
    ├── hashcat_cracker.py  # Hashcat cracking + .cap → .hc22000 converter
    ├── updater.py       # Auto-update via git pull
    └── setup.py         # OS detection, auto-setup
```

## Legal

For authorized security testing and education only. Unauthorized use is illegal.
