# Wi-Fi Handshake Cracker
# hashcat isn't working yet; it's been temporarily disabled, sorry

> **⚠️ hashcat (GPU acceleration) is temporarily disabled**
> The OpenCL runtime hangs on Windows with NVIDIA GPUs and we haven't found a reliable fix yet.
> The program uses **aircrack-ng (CPU)** for all cracking — no GPU for now.
> PRs or ideas to fix hashcat are welcome.

Audit WPA/WPA2 networks by cracking pre-captured handshakes. Cross-platform (Windows + Linux), fully automatic setup.

## Screenshots
<img width="1005" height="896" alt="22-07-2026_15-08" src="https://github.com/user-attachments/assets/43b236e3-3ba4-4525-afbe-1a5e0b28940d" />

## Features

- **Custom wordlist** — Choose between the default wordlist or your own `.txt` file at runtime
- **Zero-config** — Auto-installs Python packages, downloads aircrack-ng, and fetches wordlist on first run
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

## Prerequisites

- **Python 3.8+**
- Internet connection (first-run downloads)

## Installation

```bash
git clone https://github.com/Mysteriza/handshakeCracker
cd handshakeCracker
```

The program auto-installs all dependencies on first run. No manual setup required.

## Usage

1. Place `.cap`/`.pcap` files in `handshakes/`
2. Run the program:
   ```bash
   python main.py
   ```
3. **Wordlist selection** — You'll be prompted:
   ```
   Wordlist Selection
     1. Use default wordlist (wifite.txt)
     2. Use custom wordlist file
     Choose [1/2] (default: 1):
   ```
   - **Option 1** — Uses the auto-downloaded default wordlist
   - **Option 2** — Enter a path to your own wordlist file (TAB completion supported)
4. The program validates handshakes, cracks them with aircrack-ng, and saves results to `cracked_results/`

### Manual file entry

If no `.cap`/`.pcap` files are found in `handshakes/`, you can enter file paths manually:
```
Switch to manual file entry? (y/N): y
Handshake 1 Path: /path/to/your/file.cap
(Type 'done' or 'q' to finish adding files. Use TAB for auto-completion.)
```

## Project Structure

```
handshakeCracker/
├── main.py              # Entry point
├── requirements.txt     # Python dependencies
├── wifite.txt           # Auto-downloaded default wordlist
├── handshakes/          # Place .cap/.pcap files here
├── cracked_results/     # Cracked passwords saved here
├── bin/                 # Auto-populated aircrack-ng binaries
├── hc22000_cache/       # Temporary .hc22000 conversion cache
└── src/
    ├── config.py        # URLs, paths, constants
    ├── console.py       # Terminal helpers + error logging
    ├── utils.py         # Download, extraction, utilities
    ├── validator.py     # Scapy handshake validation
    ├── gpu.py           # Discrete GPU detection
    ├── cracker.py       # Aircrack-ng cracking (CPU)
    ├── hashcat_cracker.py  # Hashcat cracking + .cap → .hc22000 converter
    └── setup.py         # OS detection, auto-setup
```

## Legal

For authorized security testing and education only. Unauthorized use is illegal.
