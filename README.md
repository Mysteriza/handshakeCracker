# Wi-Fi Handshake Cracker

![Repo Size](https://img.shields.io/github/repo-size/Mysteriza/handshakeCracker?style=flat-square&color=blue)

Audit WPA/WPA2 networks by cracking pre-captured handshakes. Cross-platform (Windows + Linux), fully automatic setup.

## Screenshots
<img width="1005" height="896" alt="22-07-2026_15-08" src="https://github.com/user-attachments/assets/43b236e3-3ba4-4525-afbe-1a5e0b28940d" />

## Features

- **Curated wordlist** — ~8.5M real-world passwords (96 MB), filtered to 8–63 chars with no duplicates, sorted for optimal cracking
- **Custom wordlist** — Choose between the default wordlist or your own `.txt` file at runtime
- **GPU acceleration** — Hashcat (GPU) is the primary cracker; auto-falls back to aircrack-ng (CPU) only on failure
- **Smart fallback** — If hashcat exhausts all passwords without a match, skips aircrack-ng instead of wasting time
- **One-time kernel warmup** — First run compiles GPU kernels with live spinner (30-90s), cached for subsequent runs
- **Auto-Update** — Automatically checks GitHub for new commits on startup and applies them transparently without external dependencies
- **Zero-config** — Auto-installs Python packages, downloads aircrack-ng/hashcat, and fetches the curated 8.5M wordlist on first run
- **Cross-platform** — Windows auto-downloads binaries; Linux auto-installs via apt-get
- **EAPOL validation** — Scapy-based M1/M2/M3/M4 table rejects invalid captures before cracking
- **Batch processing** — Queue multiple .cap/.pcap files from `handshakes/`
- **Duplicate skip** — Skips networks already cracked in previous runs
- **Dynamic GPU Workload** — Adaptively uses `Workload 4` with Optimized Kernels (`-O`) for discrete GPUs, and safe standard kernels for integrated GPUs.
- **Diagnostic logging** — Hashcat output logged to `hc22000_cache/hashcat_debug.log` for troubleshooting
- **Debug logging** — Detailed logs written to `debug_log.txt` (rotated automatically)
- **Permission resilient** — Falls back to `%TEMP%` automatically if the project directory isn't writable

## Performance

Estimated benchmark for Hashcat mode 22000 (WPA-PBKDF2-PMKID+EAPOL) against the **8.5M password wordlist**. **Actual performance varies based on driver, thermal headroom, and laptop vs desktop variants.**

<details>
<summary><b>Click to expand Comprehensive GPU Performance Table</b></summary>

| Architecture | Device | Speed (passwords/s) | Full Wordlist (8.5M) |
|--------------|--------|:-------------------:|:--------------------:|
| CPU | 4-core Intel/AMD | ~2,000 | ~71 mins |
| iGPU | AMD Radeon Graphics (My Device) | ~31,000 | ~4.6 mins |
| **GTX 900** | GTX 960 | ~75,000 | ~114 secs |
| | GTX 970 | ~110,000 | ~77 secs |
| | GTX 980 Ti | ~170,000 | ~50 secs |
| **GTX 1000** | GTX 1050 Ti | ~80,000 | ~106 secs |
| | GTX 1060 | ~140,000 | ~61 secs |
| | GTX 1070 | ~220,000 | ~39 secs |
| | GTX 1080 Ti | ~400,000 | ~21 secs |
| **RTX 2000** | RTX 2060 | ~420,000 | ~20 secs |
| | RTX 2070 | ~540,000 | ~16 secs |
| | RTX 2080 Ti | ~880,000 | ~9.7 secs |
| **RTX 3000** | RTX 3050 | ~300,000 | ~28 secs |
| | RTX 3060 | ~450,000 | ~19 secs |
| | RTX 3060 Ti | ~580,000 | ~15 secs |
| | RTX 3070 | ~680,000 | ~13 secs |
| | RTX 3080 | ~1,050,000 | ~8.1 secs |
| | RTX 3090 | ~1,250,000 | ~6.8 secs |
| **RTX 4000** | RTX 4050 (Laptop) | ~320,000 | ~27 secs |
| | RTX 4060 | ~460,000 | ~19 secs |
| | RTX 4060 Ti | ~600,000 | ~14 secs |
| | RTX 4070 | ~820,000 | ~10 secs |
| | RTX 4070 Ti | ~1,100,000 | ~7.7 secs |
| | RTX 4080 | ~1,600,000 | ~5.3 secs |
| | RTX 4090 | ~2,500,000 | ~3.4 secs |
| **RTX 5000** | RTX 5060 | ~700,000* | ~12 secs |
| | RTX 5070 Ti | ~1,556,000 | ~5.5 secs |
| | RTX 5080 | ~2,200,000* | ~3.9 secs |
| | RTX 5090 | ~3,500,000* | ~2.4 secs |

*\*Estimated based on architectural improvements.*
</details>

> Hashcat uses **GPU** as the primary cracker. Aircrack-ng (CPU) is the fallback only if hashcat
> is unavailable or crashes during execution.

## Prerequisites

- **Python 3.10+**
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
     1. Use default wordlist (wifi-wordlist.txt)
     2. Use custom wordlist file
     Choose [1/2] (default: 1):
   ```
   - **Option 1** — Uses the auto-downloaded default wordlist (8.5M curated passwords)
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
├── wifi-wordlist.txt    # Auto-downloaded default wordlist (8.5M passwords)
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
