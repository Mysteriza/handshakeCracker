# Wi-Fi Handshake Cracker

Audit WPA/WPA2 networks by cracking pre-captured handshakes. Cross-platform (Windows + Linux), fully automatic setup.

## Screenshots
<img width="1005" height="896" alt="22-07-2026_15-08" src="https://github.com/user-attachments/assets/43b236e3-3ba4-4525-afbe-1a5e0b28940d" />

## Features

- **Custom wordlist** — Choose between the default wordlist or your own `.txt` file at runtime
- **GPU acceleration** — Hashcat (GPU) is the primary cracker; auto-falls back to aircrack-ng (CPU) only on failure
- **Smart fallback** — If hashcat exhausts all passwords without a match, skips aircrack-ng instead of wasting time
- **One-time kernel warmup** — First run compiles GPU kernels with live spinner (30-90s), cached for subsequent runs
- **Zero-config** — Auto-installs Python packages, downloads aircrack-ng/hashcat, and fetches wordlist on first run
- **Cross-platform** — Windows auto-downloads binaries; Linux auto-installs via apt-get
- **EAPOL validation** — Scapy-based M1/M2/M3/M4 table rejects invalid captures before cracking
- **Batch processing** — Queue multiple .cap/.pcap files from `handshakes/`
- **Duplicate skip** — Skips networks already cracked in previous runs
- **Dynamic parallelism** — CPU mode uses 50% of cores at BELOW_NORMAL priority
- **Diagnostic logging** — Hashcat output logged to `hc22000_cache/hashcat_debug.log` for troubleshooting
- **Debug logging** — Detailed logs written to `debug_log.txt`
- **Permission resilient** — Falls back to `%TEMP%` automatically if the project directory isn't writable

## Performance

| Method | Device | Speed (PMK/s) | 10M passwords |
|--------|--------|:------------:|:-------------:|
| CPU (aircrack-ng) | 4-core laptop | ~2,000 | ~83 minutes |
| CPU (aircrack-ng) | 16-core desktop | ~8,000 | ~21 minutes |
| GPU (hashcat + GTX 1060) | Dedicated GPU | ~300,000 | ~33 seconds |
| GPU (hashcat + RTX 3080) | Dedicated GPU | ~1,200,000 | ~8 seconds |

> Hashcat uses **GPU** as the primary cracker. Aircrack-ng (CPU) is the fallback only if hashcat
> is unavailable or crashes during execution.

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
4. The program validates handshakes, cracks them **(GPU via hashcat by default, CPU via aircrack-ng only if hashcat fails)**, and saves results to `cracked_results/`

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
├── bin/                 # Auto-populated aircrack-ng & hashcat binaries
├── hc22000_cache/       # Temporary .hc22000 conversion cache + hashcat potfile
└── src/
    ├── config.py        # URLs, paths, constants
    ├── console.py       # Terminal helpers + error logging
    ├── gpu.py           # GPU detection (informational)
    ├── utils.py          # Download, extraction, utilities
    ├── validator.py      # Scapy handshake validation
    ├── cracker.py        # Aircrack-ng cracking (CPU)
    ├── hashcat_cracker.py  # Hashcat cracking + .cap → .hc22000 converter
    └── setup.py          # OS detection, auto-setup
```

## Legal

For authorized security testing and education only. Unauthorized use is illegal.
