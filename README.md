# Wi-Fi Handshake Cracker

Audit WPA/WPA2 networks by cracking pre-captured handshakes. Cross-platform (Windows + Linux), fully automatic setup.

> **Note:** hashcat GPU acceleration is currently broken on Windows with NVIDIA GPUs (OpenCL runtime hangs). hashcat is tried first if a discrete GPU is detected, then falls back to aircrack-ng (CPU). PRs welcome if you know how to fix it.

## Screenshots
<img width="1005" height="896" alt="22-07-2026_15-08" src="https://github.com/user-attachments/assets/43b236e3-3ba4-4525-afbe-1a5e0b28940d" />

## Features

- **GPU acceleration** — Auto-detects discrete GPU (NVIDIA/AMD) and tries hashcat first; falls back to CPU aircrack-ng automatically (hashcat broken on NVIDIA Windows — known OpenCL issue)
- **Zero-config** — Auto-installs Python packages, downloads aircrack-ng/hashcat, and fetches wordlist on first run
- **Cross-platform** — Windows auto-downloads binaries; Linux auto-installs via apt-get
- **EAPOL validation** — Scapy-based M1/M2/M3/M4 table rejects invalid captures before cracking
- **Batch processing** — Queue multiple .cap/.pcap files from `handshakes/`
- **Duplicate skip** — Skips networks already cracked in previous runs
- **Dynamic parallelism** — CPU mode uses 50% of cores at BELOW_NORMAL priority
- **Error logging** — All errors written to timestamped `error_log_*.txt`
- **Permission resilient** — Falls back to `%TEMP%` automatically if the project directory isn't writable

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
```

The program auto-installs all dependencies on first run. No manual setup required.
1. Place .cap/.pcap files in `handshakes/`
2. Run the program:
```bash
python main.py
```

3. It auto-detects GPU → tries hashcat (falls back to aircrack-ng), validates handshakes with Scapy, and cracks them

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
    └── setup.py         # OS detection, auto-setup
```

## Legal

For authorized security testing and education only. Unauthorized use is illegal.
