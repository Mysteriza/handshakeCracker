import os
import re
import sys
import time
import tempfile
import platform
import subprocess

from scapy.all import rdpcap
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeResp, Dot11Elt
from scapy.layers.eap import EAPOL, EAPOL_KEY

from src.console import console, colored_log, log_error
from src.config import BIN_DIR, HASHCAT_VERSION, HASHCAT_URL, HCOV_DIR, DEPS_DIR, HASHCAT_ARCHIVE_NAME
from src.utils import download_with_progress, sanitize_ssid


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
        return found
    root = _get_root()
    local = os.path.join(root, BIN_DIR, f"hashcat-{HASHCAT_VERSION}", exe)
    if os.path.isfile(local):
        return local
    return None


def _ensure_py7zr():
    try:
        import py7zr
        return True
    except ImportError:
        try:
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", "py7zr", "-q"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            import py7zr
            return True
        except Exception:
            return False


def ensure_hashcat() -> bool:
    if get_hashcat_path():
        return True

    root = _get_root()
    dest_dir = os.path.join(root, BIN_DIR)
    os.makedirs(dest_dir, exist_ok=True)

    tmp_path = None
    try:
        local_archive = os.path.join(root, DEPS_DIR, HASHCAT_ARCHIVE_NAME)
        if os.path.isfile(local_archive):
            colored_log("info", f"Found local hashcat archive, extracting...")
            if not _ensure_py7zr():
                return False
            import py7zr
            with py7zr.SevenZipFile(local_archive, mode='r') as z:
                z.extractall(path=dest_dir)
            if get_hashcat_path():
                colored_log("success", f"hashcat {HASHCAT_VERSION} ready.")
                return True
            colored_log("warning", "Local hashcat extraction failed — trying download.")

        if not _ensure_py7zr():
            colored_log("error", "Failed to install py7zr (needed to extract hashcat).")
            return False
        import py7zr

        tmp = tempfile.NamedTemporaryFile(suffix='.7z', delete=False)
        tmp_path = tmp.name
        tmp.close()

        if not download_with_progress(HASHCAT_URL, tmp_path, "Downloading hashcat"):
            return False

        colored_log("info", "Extracting hashcat...")
        with py7zr.SevenZipFile(tmp_path, mode='r') as z:
            z.extractall(path=dest_dir)

        if get_hashcat_path():
            colored_log("success", f"hashcat {HASHCAT_VERSION} ready.")
            return True

        colored_log("error", "hashcat extraction completed but binary not found.")
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
            except OSError:
                pass


def add_bin_to_path():
    hc = get_hashcat_path()
    if hc:
        parent = os.path.dirname(hc)
        if parent not in os.environ.get("PATH", ""):
            os.environ["PATH"] = parent + os.pathsep + os.environ.get("PATH", "")


def _classify_eapol(ek) -> str | None:
    ack = bool(ek.key_ack)
    mic = bool(ek.has_key_mic)
    ins = bool(ek.install)
    sec = bool(ek.secure)
    if ack and not mic and not ins and not sec:
        return "M1"
    if not ack and mic and not ins and not sec:
        return "M2"
    if ack and mic and ins and sec:
        return "M3"
    if not ack and mic and not ins and sec:
        return "M4"
    return None


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
    return bytes(pkt[EAPOL])


def convert_cap_to_hc22000(cap_path: str, output_path: str) -> bool:
    try:
        packets = rdpcap(cap_path)
    except Exception as e:
        log_error(f"Failed to read {cap_path}", e)
        return False

    essid = ""
    ap_mac = None
    sta_mac = None
    anonce = None
    snonce = None
    mic = None
    key_ver = None
    eapol_raw_bytes = None

    frames = {}

    for pkt in packets:
        if pkt.haslayer(Dot11Beacon):
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

    if "M2" not in frames:
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

    # Get raw EAPOL bytes from M2
    eapol_raw_bytes = _extract_raw_eapol(m2_pkt)

    if not all([ap_mac, sta_mac, anonce, snonce, mic, key_ver, eapol_raw_bytes]):
        return False

    if not essid:
        essid = "Unknown"

    pmkid = "00" * 16
    essid_hex = essid.encode('utf-8', errors='replace').hex()
    eapol_hex = eapol_raw_bytes.hex()

    line = (
        f"WPA*01*{pmkid}*{ap_mac}*{sta_mac}*{essid_hex}*"
        f"{anonce}*{snonce}*{mic}*{key_ver}*{eapol_hex}*"
    )

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, 'w') as f:
        f.write(line + '\n')

    return True


_SPINNER_CHARS = ['-', '\\', '|', '/']


def _write_status(spin_char: str, msg: str):
    sys.stdout.write(f"\r  {spin_char} {msg:<66}\r")
    sys.stdout.flush()


def _clear_status():
    sys.stdout.write("\r" + " " * 80 + "\r")
    sys.stdout.flush()


def _parse_progress(line: str) -> dict:
    data = {}
    m_speed = re.search(r'(\d+\.\d+\s*[kMG]?H/s)', line)
    if m_speed:
        data['speed'] = m_speed.group(1)
    m_prog = re.search(r'(\d+\.?\d*)\s*/\s*(\d+\.?\d*)', line)
    if m_prog:
        data['progress'] = f"{m_prog.group(1)}/{m_prog.group(2)}"
    m_time = re.search(r'(\d+:\d+:\d+)', line)
    if m_time:
        data['time'] = m_time.group(1)
    m_guess = re.search(r'\((.+?)\)', line)
    if m_guess:
        data['guess'] = m_guess.group(1)
    return data


def crack_with_hashcat(hc22000_path: str, wordlist_path: str, display_essid: str) -> str | None:
    start_time = time.time()
    hc_exe = get_hashcat_path()
    if not hc_exe:
        return None

    os.makedirs(HCOV_DIR, exist_ok=True)
    potfile = os.path.join(HCOV_DIR, "hashcat.potfile")

    cmd = [
        hc_exe, "-m", "22000", "-a", "0",
        "--status", "--status-timer=1",
        "--potfile-path", potfile,
        "--quiet",
        hc22000_path, wordlist_path,
    ]

    proc = None
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding='utf-8', errors='replace',
            creationflags=subprocess.CREATE_NO_WINDOW if _SYSTEM == "Windows" else 0,
        )

        if _SYSTEM == "Windows":
            try:
                import ctypes
                k32 = ctypes.windll.kernel32
                h = k32.OpenProcess(0x1F0FFF, False, proc.pid)
                if h:
                    k32.SetPriorityClass(h, 0x00004000)
                    k32.CloseHandle(h)
            except Exception:
                pass

        msg_queue = [
            f"Hashcat cracking {display_essid}... Initializing...",
            f"Hashcat cracking {display_essid}... Loading kernel...",
            f"Hashcat cracking {display_essid}... Running on GPU...",
            f"Hashcat cracking {display_essid}... Testing candidates...",
            f"Hashcat cracking {display_essid}... Almost there...",
        ]
        msg_idx = 0
        spin_idx = 0
        last_switch = time.time()

        password = None

        for raw_line in proc.stdout:
            line = raw_line.rstrip()

            if not line:
                continue

            status_keywords = {"Cracked", "Cracking", "Progress", "Status",
                               "Speed", "GPU", "Started", "Session", "Memory",
                               "ctr", "Time.Est", "Time.Start"}
            if any(kw in line for kw in status_keywords):
                info = _parse_progress(line)
                parts = []
                if 'speed' in info:
                    parts.append(info['speed'])
                if 'progress' in info:
                    parts.append(info['progress'])
                if 'time' in info:
                    parts.append(info['time'])
                display = " | ".join(parts) if parts else "running..."

                spin_idx += 1
                now = time.time()
                if now - last_switch >= 6:
                    msg_idx = (msg_idx + 1) % len(msg_queue)
                    last_switch = now

                _write_status(_SPINNER_CHARS[spin_idx % 4],
                              f"Hashcat {display_essid}: {display}")
                continue

            if "Exhausted" in line or "Quit" in line or "Killed" in line:
                break

            if ":" in line:
                idx = line.rfind(":")
                pw_candidate = line[idx + 1:].strip()
                if pw_candidate and len(pw_candidate) < 128:
                    password = pw_candidate

        if proc:
            proc.wait()

        _clear_status()

        if password:
            elapsed = time.time() - start_time
            m, s = divmod(int(elapsed), 60)
            time_str = f"{m:02d}:{s:02d}"

            console.print(f"  Password: {password}")
            console.print(f"  Time: {time_str}")
            return password

        if not password and os.path.exists(potfile):
            with open(potfile) as f:
                for line in f:
                    if ':' in line:
                        idx = line.rfind(':')
                        pw_candidate = line[idx + 1:].strip()
                        if pw_candidate and len(pw_candidate) < 128:
                            password = pw_candidate
                            break

        return None

    except KeyboardInterrupt:
        if proc:
            try:
                proc.terminate()
            except Exception:
                pass
        _clear_status()
        colored_log("warning", "Hashcat cracking interrupted by user.")
        return None
    except Exception as e:
        if proc:
            try:
                proc.terminate()
            except Exception:
                pass
        log_error("Hashcat execution failed", e)
        _clear_status()
        return None


def hashcat_crack_handshake(
    handshake_path: str, wordlist_path: str, display_essid: str
) -> str | None:
    if not ensure_hashcat():
        return None

    add_bin_to_path()

    colored_log("info", "Converting .cap to hashcat format (hc22000)...")
    hc22000_path = os.path.join(
        HCOV_DIR,
        os.path.basename(handshake_path).replace(".cap", "").replace(".pcap", "") + ".hc22000"
    )

    if not convert_cap_to_hc22000(handshake_path, hc22000_path):
        colored_log("error", "Failed to convert .cap to hc22000 format.")
        return None

    result = crack_with_hashcat(hc22000_path, wordlist_path, display_essid)

    # Cleanup
    try:
        os.remove(hc22000_path)
    except OSError:
        pass

    return result
