import os
import re
import sys
import time
import tempfile
import platform
import subprocess

from scapy.all import rdpcap
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt
from scapy.layers.eap import EAPOL, EAPOL_KEY

from src.console import console, colored_log, log_error, log_debug
from src.config import BIN_DIR, HASHCAT_VERSION, HASHCAT_URL, HCOV_DIR, DEPS_DIR, HASHCAT_ARCHIVE_NAME, RESULTS_DIR
from src.utils import download_with_progress, sanitize_ssid
from src.validator import _classify_eapol


_SYSTEM = platform.system()


def _find_in_path(name: str) -> str | None:
    for d in os.environ.get("PATH", "").split(os.pathsep):
        p = os.path.join(d.strip('"'), name)
        if os.path.isfile(p):
            return p
    return None


def _get_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def get_hashcat_path() -> str | None:
    exe = "hashcat.exe" if _SYSTEM == "Windows" else "hashcat"
    found = _find_in_path(exe)
    if found:
        log_debug(f"get_hashcat_path: found in PATH: {found}")
        return found
    root = _get_root()
    local = os.path.join(root, BIN_DIR, f"hashcat-{HASHCAT_VERSION}", exe)
    if os.path.isfile(local):
        log_debug(f"get_hashcat_path: found locally: {local}")
        return local
    log_debug(f"get_hashcat_path: not found (checked PATH and {local})")
    return None


def _extract_archive(archive: str, dest: str) -> bool:
    if not os.path.isfile(archive):
        log_error(f"_extract_archive: archive not found: {archive}")
        return False

    log_debug(f"_extract_archive: archive={archive} dest={dest}")

    extractor_name = "7z"
    try:
        if _SYSTEM == "Windows":
            sz = os.path.join(dest, "7zr.exe")
            if not os.path.isfile(sz):
                colored_log("info", "Downloading 7-Zip standalone extractor...")
                log_debug("_extract_archive: downloading 7zr.exe")
                from src.utils import download_with_progress
                download_with_progress(
                    "https://www.7-zip.org/a/7zr.exe", sz,
                    "Downloading 7zr")
            extractor = [sz, "x", archive, f"-o{dest}", "-y"]
            extractor_name = "7zr"
        else:
            # Linux / macOS: use system 7z (p7zip-full)
            extractor = ["7z", "x", archive, f"-o{dest}", "-y"]

        log_debug(f"_extract_archive: extracting with {extractor[0]} from {archive}")
        r = subprocess.run(
            extractor,
            capture_output=True, text=True, timeout=120)
        ok = r.returncode == 0
        log_debug(f"_extract_archive: {extractor[0]} exit code={r.returncode} ok={ok}")
        if not ok:
            log_debug(f"_extract_archive: {extractor[0]} stderr", r.stderr[:500])
        return ok
    except FileNotFoundError:
        log_error("7z not found. Install it: sudo apt-get install p7zip-full  (or  brew install p7zip on macOS)")
        return False
    except Exception as e:
        log_debug(f"_extract_archive: {extractor_name} exception", str(e))
        return False


def ensure_hashcat() -> bool:
    found = get_hashcat_path()
    log_debug(f"ensure_hashcat: get_hashcat_path() returned {found!r}")
    if found:
        log_debug("ensure_hashcat: hashcat already available")
        return True

    root = _get_root()
    dest_dir = os.path.join(root, BIN_DIR)
    os.makedirs(dest_dir, exist_ok=True)

    tmp_path = None
    try:
        local_archive = os.path.join(root, DEPS_DIR, HASHCAT_ARCHIVE_NAME)
        log_debug(f"ensure_hashcat: checking local archive: {local_archive} exists={os.path.isfile(local_archive)}")
        if os.path.isfile(local_archive):
            colored_log("info", f"Found local hashcat archive, extracting...")
            ok = _extract_archive(local_archive, dest_dir)
            log_debug(f"ensure_hashcat: local extraction result={ok}")
            if ok and get_hashcat_path():
                colored_log("success", f"hashcat {HASHCAT_VERSION} ready.")
                return True
            colored_log("warning", "Local hashcat extraction failed — trying download.")

        log_debug(f"ensure_hashcat: downloading from {HASHCAT_URL}")
        tmp = tempfile.NamedTemporaryFile(suffix='.7z', delete=False)
        tmp_path = tmp.name
        tmp.close()
        log_debug(f"ensure_hashcat: temp download path: {tmp_path}")

        if not download_with_progress(HASHCAT_URL, tmp_path, "Downloading hashcat"):
            log_error("ensure_hashcat: download failed")
            return False
        log_debug("ensure_hashcat: download OK, extracting")

        colored_log("info", "Extracting hashcat...")
        if _extract_archive(tmp_path, dest_dir):
            if get_hashcat_path():
                colored_log("success", f"hashcat {HASHCAT_VERSION} ready.")
                return True

        colored_log("error", "hashcat extraction failed.")
        return False

    except KeyboardInterrupt:
        colored_log("warning", "Hashcat setup interrupted by user.")
        return False
    except Exception as e:
        log_error("Failed to download/extract hashcat", e)
        return False
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
                log_debug("ensure_hashcat: cleaned up temp file")
            except OSError:
                pass


def _kernel_cache_exists(hc_dir: str) -> bool:
    """Check if Hashcat has compiled kernel binaries for mode 22000 already."""
    # Hashcat stores compiled kernels in <hashcat_dir>/kernels/
    kernels_dir = os.path.join(hc_dir, "kernels")
    if not os.path.isdir(kernels_dir):
        return False
    # Any .bin file indicates kernels have been compiled at least once
    for fname in os.listdir(kernels_dir):
        if fname.endswith(".bin"):
            return True
    return False


def _line_is_noise(line: str) -> bool:
    """Return True if a hashcat status line should be filtered from user display."""
    if not line:
        return True
    # Hash content lines
    if line.startswith("WPA*02*") or line.startswith("$WPAPSK$"):
        return True
    # Status / statistics lines
    noise_prefixes = [
        "Session..........:",
        "Status...........:",
        "Hash.Target......:",
        "Time.Started.....:",
        "Time.Estimated...:",
        "Speed.Chars/sec..:",
        "Speed.Dev.#",
        "Speed.GPU.#",
        "Progress.........:",
        "Restore.Point....:",
        "Restore.Subsec...:",
        "Candidate.Engine.:",
        "Candidates.......:",
        "HWMon.GPU.#",
        "HWMon.Dev.#",
        "Started.........:",
        "Stopped.........:",
        "Input.Mode......:",
        "Watchdog........:",
        "[s]tatus",
        "[p]ause",
        "[b]ypass",
        "[c]heckpoint",
        "[q]uit",
        "The password was found",
        "Password found on device",
    ]
    return any(line.startswith(p) for p in noise_prefixes)


def warmup_hashcat_kernel() -> bool:
    hc_exe = get_hashcat_path()
    if not hc_exe:
        return False

    hc_dir = os.path.dirname(hc_exe)

    if _kernel_cache_exists(hc_dir):
        log_debug("warmup_hashcat_kernel: kernel cache found, skipping compilation")
        colored_log("info", "GPU kernel cache found — compilation not required.")
        return True

    dummy_hc22000 = os.path.join(HCOV_DIR, "_warmup.hc22000")
    dummy_wordlist = os.path.join(HCOV_DIR, "_warmup_wl.txt")

    os.makedirs(HCOV_DIR, exist_ok=True)
    with open(dummy_hc22000, "w") as f:
        f.write("WPA*02*b8035c6e92ac3356137ea51548f9f7d0*68f543f3a778*803049625845*4b6f73616e206275206e617461*477909d5740b55afe8867db5fe6ddbaa19e22d26af3dad161c06b6094bb76e36*0103007502010a00000000000000000001542d23323f1e5b333deb4c57c669c62f743ae44ab763ad8e2e73f2016b74503c00000000000000000000000000000000000000000000\n")
    with open(dummy_wordlist, "w") as f:
        f.write("testpassword\n")

    potfile = os.path.join(HCOV_DIR, "_warmup.potfile")
    cmd = [
        hc_exe, "-m", "22000", "-a", "0",
        "-w", "1",
        "--potfile-path", potfile,
        dummy_hc22000, dummy_wordlist,
    ]

    try:
        log_debug("warmup_hashcat_kernel: no kernel cache found, running first-time compilation")

        # ── Banner ──────────────────────────────────────────────────
        console.rule("[bold yellow]GPU Kernel Compilation (First Run)[/bold yellow]", style="yellow")
        console.print("")
        colored_log("info", "Compiling GPU kernel for WPA/WPA2 mode (hashcat -m 22000)...")
        console.print("  [dim]Hashcat needs to compile the GPU kernel once.[/dim]")
        console.print("  [dim]Time: ~30-90 seconds depending on GPU and driver.[/dim]")
        console.print("  [dim]Compiled kernels are cached — next run will be ready instantly.[/dim]")
        console.print("")

        start = time.time()
        device_found = False
        kernel_compiling = False

        # Do NOT use CREATE_NO_WINDOW — it breaks Hashcat stdout pipe on Windows
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding='utf-8', errors='replace',
            cwd=hc_dir,
        )

        assert proc.stdout is not None, "stdout pipe not created"

        for line in proc.stdout:
            line_str = line.rstrip('\n\r')

            if _line_is_noise(line_str):
                continue

            # Highlight device detection lines
            if line_str.startswith("* Device #"):
                device_found = True
                console.print(f"  [cyan]▸[/cyan] [bold]{line_str}[/bold]")
                continue

            # Highlight kernel compilation message
            if "Kernels compiled" in line_str or "compiling device kernel" in line_str:
                kernel_compiling = True
                console.print(f"  [yellow]⚡[/yellow] [bold]{line_str}[/bold]")
                continue

            # Show kernel notices (ptxas info etc.)
            if "Kernel.Notices" in line_str or "ptxas info" in line_str:
                console.print(f"  [dim]ℹ[/dim] {line_str}")
                continue

            # Show hashcat version banner
            if line_str.startswith("hashcat "):
                console.print(f"  [green]▶[/green] {line_str}")
                continue

            # Everything else meaningful
            if line_str:
                console.print(f"  [white]│[/white] {line_str}")

        proc.wait(timeout=300)
        elapsed = time.time() - start
        log_debug(f"warmup_hashcat_kernel: finished in {elapsed:.2f}s (rc={proc.returncode})")

        console.print("")

        if proc.returncode == 0:
            if elapsed > 5:
                colored_log("success", f"GPU kernel compilation completed ({int(elapsed)}s). Cache saved.")
            else:
                colored_log("success", "GPU kernel is ready to use.")
        else:
            colored_log("warning", "GPU kernel compilation failed — falling back to aircrack-ng (CPU).")

        console.rule(style="yellow")
        return proc.returncode == 0

    except Exception as e:
        log_debug(f"warmup_hashcat_kernel: failed ({e})")
        return False
    finally:
        for f in [dummy_hc22000, dummy_wordlist, potfile]:
            if os.path.exists(f):
                try:
                    os.remove(f)
                except OSError:
                    pass


def add_bin_to_path():
    hc = get_hashcat_path()
    if hc:
        parent = os.path.dirname(hc)
        if parent not in os.environ.get("PATH", ""):
            old = os.environ.get("PATH", "")
            os.environ["PATH"] = parent + os.pathsep + old
            log_debug(f"add_bin_to_path: prepended {parent} to PATH")
        else:
            log_debug(f"add_bin_to_path: {parent} already in PATH")
    else:
        log_debug("add_bin_to_path: hashcat not found, nothing to add")


def _format_mac(mac) -> str:
    if isinstance(mac, str):
        mac = mac.replace("-", ":").replace(" ", "")
        parts = mac.split(":")
        if len(parts) == 6:
            return ":".join(f"{p.lower():0>2s}" for p in parts)
        mac = mac.replace(":", "")
        try:
            b = bytes.fromhex(mac)
            return ":".join(f"{x:02x}" for x in b)
        except ValueError:
            return "00:00:00:00:00:00"
    if isinstance(mac, bytes):
        if len(mac) == 6:
            return ":".join(f"{x:02x}" for x in mac)
        return "00:00:00:00:00:00"
    return "00:00:00:00:00:00"


def _extract_raw_eapol(pkt) -> bytes | None:
    try:
        return bytes(pkt[EAPOL])
    except (IndexError, Exception):
        return None


def convert_cap_to_hc22000(cap_path: str, output_path: str) -> bool:
    log_debug(f"convert_cap_to_hc22000: reading {cap_path}")
    try:
        packets = rdpcap(cap_path)
    except Exception as e:
        log_error(f"Failed to read {cap_path}", e)
        return False

    log_debug(f"convert_cap_to_hc22000: loaded {len(packets)} packet(s) from cap")

    essid = ""
    ap_mac = None
    sta_mac = None
    anonce = None
    snonce = None
    mic = None
    key_ver = None
    eapol_raw_bytes = None

    frames = {}
    beacon_count = 0

    for pkt in packets:
        if pkt.haslayer(Dot11Beacon):
            beacon_count += 1
            elt = pkt[Dot11Elt]
            while elt:
                if elt.ID == 0 and elt.info:
                    try:
                        essid = elt.info.decode('utf-8', errors='replace')
                    except Exception:
                        essid = elt.info.hex()
                    if not ap_mac:
                        ap_mac = _format_mac(pkt[Dot11].addr2)
                    break
                elt = elt.payload if isinstance(elt.payload, Dot11Elt) else None

        if not pkt.haslayer(EAPOL_KEY):
            continue
        ek = pkt[EAPOL_KEY]
        msg = _classify_eapol(ek)
        if msg:
            frames[msg] = pkt

    log_debug(f"convert_cap_to_hc22000: beacons={beacon_count} EAPOL frames found={list(frames.keys())}")

    if "M2" not in frames:
        log_debug("convert_cap_to_hc22000: M2 not found in capture")
        return False

    # Get MACs
    m2_pkt = frames["M2"]
    m2_ek = m2_pkt[EAPOL_KEY]

    if ap_mac:
        if m2_pkt.haslayer(Dot11):
            s = m2_pkt[Dot11].addr2
            if _format_mac(s) != ap_mac:
                sta_mac = _format_mac(s)
            else:
                sta_mac = _format_mac(m2_pkt[Dot11].addr1)
    elif m2_pkt.haslayer(Dot11):
        ap_mac = _format_mac(m2_pkt[Dot11].addr1)
        sta_mac = _format_mac(m2_pkt[Dot11].addr2)

    # Get ANonce from M1 or M3
    if "M1" in frames:
        anonce = bytes(frames["M1"][EAPOL_KEY].key_nonce).hex()
        if not ap_mac and frames["M1"].haslayer(Dot11):
            ap_mac = _format_mac(frames["M1"][Dot11].addr2)
    elif "M3" in frames:
        anonce = bytes(frames["M3"][EAPOL_KEY].key_nonce).hex()

    # Get SNonce, MIC, key version from M2
    snonce = bytes(m2_ek.key_nonce).hex()
    mic = bytes(m2_ek.key_mic).hex()
    key_ver = m2_ek.key_descriptor_type_version

    # Get raw EAPOL bytes from M2 (trim to declared body length)
    eapol_raw_bytes = _extract_raw_eapol(m2_pkt)
    if eapol_raw_bytes is None:
        log_debug("convert_cap_to_hc22000: failed to extract raw EAPOL bytes from M2")
        return False

    declared_len = 4 + m2_pkt[EAPOL].len
    if eapol_raw_bytes is not None and len(eapol_raw_bytes) > declared_len:
        log_debug(f"convert_cap_to_hc22000: trimming EAPOL from {len(eapol_raw_bytes)} to {declared_len} (body len {m2_pkt[EAPOL].len})")
        eapol_raw_bytes = eapol_raw_bytes[:declared_len]

    log_debug(f"convert_cap_to_hc22000: extracted ap_mac={ap_mac} sta_mac={sta_mac}")
    log_debug(f"convert_cap_to_hc22000: anonce_len={len(anonce or '')} snonce_len={len(snonce or '')} mic_len={len(mic or '')} key_ver={key_ver}")
    log_debug(f"convert_cap_to_hc22000: eapol_raw_bytes_len={len(eapol_raw_bytes or b'')}")

    if not all([ap_mac, sta_mac, anonce, snonce, mic, key_ver]):
        log_debug(f"convert_cap_to_hc22000: validation failed - missing fields: ap={bool(ap_mac)} sta={bool(sta_mac)} anonce={bool(anonce)} snonce={bool(snonce)} mic={bool(mic)} kv={bool(key_ver)}")
        return False

    # Narrow types: after the all() guard above, these are guaranteed truthy
    assert ap_mac is not None
    assert sta_mac is not None
    assert anonce is not None
    assert snonce is not None
    assert mic is not None
    assert key_ver is not None
    assert eapol_raw_bytes is not None

    if not essid:
        essid = "Unknown"

    essid_hex = essid.encode('utf-8', errors='replace').hex()

    if len(eapol_raw_bytes) < 81 + 16:
        log_error("convert_cap_to_hc22000: EAPOL frame too short for MIC zeroing", Exception(f"len={len(eapol_raw_bytes)}"))
        return False

    eapol_bytes = bytearray(eapol_raw_bytes)
    orig_mic = bytes(eapol_bytes[81:97]).hex()
    eapol_bytes[81:97] = b'\x00' * 16
    eapol_hex = bytes(eapol_bytes).hex()
    log_debug(f"convert_cap_to_hc22000: zeroed MIC in EAPOL frame original_mic_start={orig_mic[:16]}...")

    assert ap_mac is not None
    assert sta_mac is not None
    assert anonce is not None
    ap_mac_no_colon = ap_mac.replace(":", "")
    sta_mac_no_colon = sta_mac.replace(":", "")

    line = (
        f"WPA*02*{mic}*{ap_mac_no_colon}*{sta_mac_no_colon}*{essid_hex}*"
        f"{anonce}*{eapol_hex}*00"
    )

    log_debug(f"convert_cap_to_hc22000: writing hc22000 file to {output_path}")
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, 'w') as f:
        f.write(line + '\n')

    log_debug(f"convert_cap_to_hc22000: OK essid={essid!r} ap={ap_mac_no_colon} sta={sta_mac_no_colon} anonce_len={len(anonce)} eapol_len={len(eapol_hex)}")
    return True






def _log_hashcat_output(heading: str, lines: list[str]):
    log_path = os.path.join(HCOV_DIR, "hashcat_debug.log")
    try:
        with open(log_path, 'a', encoding='utf-8') as f:
            f.write(f"\n=== {heading} ===\n")
            for l in lines:
                f.write(l + '\n')
    except Exception:
        pass


def crack_with_hashcat(hc22000_path: str, wordlist_path: str, display_essid: str) -> str | None:
    start_time = time.time()
    hc_exe = get_hashcat_path()
    log_debug(f"crack_with_hashcat: start hc_exe={hc_exe!r} hc22000={hc22000_path} wordlist={wordlist_path}")
    if not hc_exe:
        log_error("crack_with_hashcat: hashcat binary not found")
        return None

    hc_dir = os.path.dirname(hc_exe)
    os.makedirs(HCOV_DIR, exist_ok=True)
    potfile = os.path.join(HCOV_DIR, "hashcat.potfile")
    log_debug(f"crack_with_hashcat: potfile={potfile} hc_dir={hc_dir}")

    _log_hashcat_output("DIAG", [f"Hashcat EXE: {hc_exe}", f"hc22000: {hc22000_path}", f"wordlist: {wordlist_path}", f"CWD: {hc_dir}"])

    try:
        with open(hc22000_path, 'r') as _f:
            content = _f.read().strip()
        _log_hashcat_output("HC22000 content", [content[:300]])
        log_debug(f"crack_with_hashcat: hc22000 file length={len(content)} starts_with={content[:80]}")
    except Exception as e:
        log_error("Failed to read hc22000 file", e)
        return None

    try:
        log_debug(f"crack_with_hashcat: testing hashcat binary with --version (cwd={hc_dir})")
        ver = subprocess.run([hc_exe, "--version"], capture_output=True, text=True, timeout=30, cwd=hc_dir)
        _log_hashcat_output("hashcat --version", [ver.stdout.strip(), ver.stderr.strip(), f"rc={ver.returncode}"])
        log_debug(f"crack_with_hashcat: hashcat --version stdout={ver.stdout.strip()!r} stderr={ver.stderr.strip()!r} rc={ver.returncode}")
        if ver.returncode != 0:
            log_error("hashcat binary test failed", Exception(f"rc={ver.returncode} stderr={ver.stderr}"))
            return None
    except Exception as e:
        log_error("hashcat binary test threw exception", e)
        return None

    log_debug("crack_with_hashcat: killing any lingering hashcat process")
    try:
        subprocess.run(["taskkill", "/f", "/im", "hashcat.exe"], capture_output=True, timeout=10)
    except Exception:
        pass

    cmd = [
        hc_exe, "-m", "22000", "-a", "0",
        "-w", "4", "-O",
        "--potfile-path", potfile,
        hc22000_path, wordlist_path,
    ]

    cmd_str = " ".join(cmd)
    _log_hashcat_output("COMMAND", [cmd_str])
    log_debug(f"crack_with_hashcat: running command: {cmd_str}")

    proc = None
    import threading
    _spinner_stop = threading.Event()

    def _spinner_thread():
        chars = ['-', '\\', '|', '/']
        msg_queue = [
            f"Hashcat cracking {display_essid}... Initializing kernels (may take 30-60s)...",
            f"Hashcat cracking {display_essid}... Running...",
            f"Hashcat cracking {display_essid}... Testing candidates...",
            f"Hashcat cracking {display_essid}... Almost there...",
        ]
        idx = 0
        last_switch = time.time()
        c = 0
        while not _spinner_stop.is_set():
            now = time.time()
            if now - last_switch >= 8:
                idx = (idx + 1) % len(msg_queue)
                last_switch = now
            sys.stdout.write(f"\r  {chars[c % 4]} {msg_queue[idx]}".ljust(110) + "\r")
            sys.stdout.flush()
            c += 1
            time.sleep(0.25)

    try:
        # Do NOT use CREATE_NO_WINDOW — it silently breaks Hashcat stdout pipe on Windows
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding='utf-8', errors='replace',
            cwd=hc_dir,
        )
        assert proc.stdout is not None, "stdout pipe not created"
        log_debug(f"crack_with_hashcat: subprocess started pid={proc.pid}")

        t = threading.Thread(target=_spinner_thread, daemon=True)
        t.start()

        hashcat_output: list[str] = []
        line_count = 0
        kernel_init_done = False

        for raw_line in proc.stdout:
            line = raw_line.rstrip()
            line_count += 1
            hashcat_output.append(line)

            # Once we see the first progress/status line, kernels are done — apply low priority
            if not kernel_init_done and line and not line.startswith("WPA*02*"):
                kernel_init_done = True
                if _SYSTEM == "Windows":
                    try:
                        import ctypes
                        k32 = ctypes.windll.kernel32
                        h = k32.OpenProcess(0x1F0FFF, False, proc.pid)
                        if h:
                            k32.SetPriorityClass(h, 0x00004000)
                            log_debug("crack_with_hashcat: kernel init done, set BELOW_NORMAL priority")
                            k32.CloseHandle(h)
                    except Exception as e:
                        log_debug("crack_with_hashcat: failed to set priority", str(e))

        proc.wait()
        hashcat_output.append(f"[PROCESS EXIT CODE: {proc.returncode}]")
        _log_hashcat_output("HASHCAT OUTPUT", hashcat_output)
        log_debug(f"crack_with_hashcat: process exited rc={proc.returncode} total_lines={line_count}")

        _spinner_stop.set()
        t.join(timeout=2)
        sys.stdout.write("\r" + " " * 110 + "\r")
        sys.stdout.flush()

        # Primary: read password from potfile — most reliable across all Hashcat versions
        password = None
        if os.path.exists(potfile):
            try:
                with open(potfile, encoding='utf-8', errors='replace') as f:
                    pot_content = f.read()
                _log_hashcat_output("POTFILE", [pot_content.strip()[:300]])
                log_debug(f"crack_with_hashcat: potfile len={len(pot_content)}")
                for pot_line in pot_content.splitlines():
                    if ':' in pot_line and not pot_line.startswith("#"):
                        pw_candidate = pot_line[pot_line.rfind(':') + 1:].strip()
                        if 8 <= len(pw_candidate) <= 63:
                            password = pw_candidate
                            log_debug(f"crack_with_hashcat: password from potfile: {password!r}")
                            break
            except Exception as pe:
                log_debug(f"crack_with_hashcat: potfile read error: {pe}")
        else:
            log_debug("crack_with_hashcat: potfile does not exist")

        if password:
            elapsed = time.time() - start_time
            m, s = divmod(int(elapsed), 60)
            time_str = f"{m:02d}:{s:02d}"
            log_debug(f"crack_with_hashcat: FOUND password={password!r} time={time_str}")
            console.print(f"  Password: {password}")
            console.print(f"  Time: {time_str}")

            os.makedirs(RESULTS_DIR, exist_ok=True)
            safe_essid = sanitize_ssid(display_essid)
            result_file = os.path.join(RESULTS_DIR, f"{safe_essid}_cracked_password.txt")
            with open(result_file, "w") as f:
                f.write(f"Network (ESSID): {display_essid}\n")
                f.write(f"Wordlist Used: {os.path.basename(wordlist_path)}\n")
                f.write(f"Password Found: {password}\n")
                f.write(f"Time Taken: {time_str}\n")

            console.print(f"  Saved to: {result_file}")
            return password

        if proc.returncode not in (0, 1):
            log_debug(f"crack_with_hashcat: hashcat exited with unexpected rc={proc.returncode}")
            diag_cmd = [hc_exe, "-m", "22000", "-a", "0", "--potfile-path", potfile, hc22000_path, wordlist_path]
            try:
                diag = subprocess.run(diag_cmd, capture_output=True, text=True, timeout=120, cwd=hc_dir)
                diag_out = f"stdout={diag.stdout[:2000]!r} stderr={diag.stderr[:2000]!r} rc={diag.returncode}"
                _log_hashcat_output("DIAGNOSTIC", [diag_out])
                log_debug("crack_with_hashcat: diagnostic run", diag_out)
            except Exception as e2:
                log_debug("crack_with_hashcat: diagnostic also failed", str(e2))

        _log_hashcat_output("RESULT", ["No password found"])
        log_debug("crack_with_hashcat: returning None (no password)")
        return None

    except FileNotFoundError as e:
        _log_hashcat_output("CRASH", [f"FileNotFoundError: {e}"])
        log_error("hashcat binary not found at path", e)
        _spinner_stop.set()
        sys.stdout.write("\r" + " " * 110 + "\r")
        sys.stdout.flush()
        return None
    except KeyboardInterrupt:
        _spinner_stop.set()
        if proc:
            try:
                proc.terminate()
            except Exception:
                pass
        sys.stdout.write("\r" + " " * 110 + "\r")
        sys.stdout.flush()
        colored_log("warning", "Hashcat cracking interrupted by user.")
        return None
    except Exception as e:
        _spinner_stop.set()
        if proc:
            try:
                proc.terminate()
            except Exception:
                pass
        log_error("Hashcat execution failed", e)
        sys.stdout.write("\r" + " " * 110 + "\r")
        sys.stdout.flush()
        return None


def hashcat_crack_handshake(
    handshake_path: str, wordlist_path: str, display_essid: str
) -> str | None:
    log_debug(f"hashcat_crack_handshake: start handshake={handshake_path} wordlist={wordlist_path} essid={display_essid!r}")

    if not ensure_hashcat():
        log_debug("hashcat_crack_handshake: ensure_hashcat returned False, aborting")
        return None

    log_debug("hashcat_crack_handshake: ensure_hashcat OK")
    add_bin_to_path()

    # Warm up GPU kernels on first run (one-time compilation, 30-90s)
    if not warmup_hashcat_kernel():
        log_debug("hashcat_crack_handshake: warmup failed, continuing anyway")
        colored_log("warning", "GPU kernel warmup skipped — hashcat may take longer on first run.")

    colored_log("info", "Converting .cap to hashcat format (hc22000)...")
    hc22000_path = os.path.join(
        HCOV_DIR,
        os.path.basename(handshake_path).replace(".cap", "").replace(".pcap", "") + ".hc22000"
    )
    log_debug(f"hashcat_crack_handshake: hc22000 output path: {hc22000_path}")

    if not convert_cap_to_hc22000(handshake_path, hc22000_path):
        colored_log("error", "Failed to convert .cap to hc22000 format.")
        log_debug("hashcat_crack_handshake: convert_cap_to_hc22000 returned False")
        return None

    log_debug(f"hashcat_crack_handshake: conversion OK, calling crack_with_hashcat")
    result = crack_with_hashcat(hc22000_path, wordlist_path, display_essid)
    log_debug(f"hashcat_crack_handshake: crack_with_hashcat returned {result!r}")

    # Cleanup
    try:
        os.remove(hc22000_path)
        log_debug(f"hashcat_crack_handshake: cleaned up temp file {hc22000_path}")
    except OSError:
        pass

    return result
