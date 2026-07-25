import os
from dataclasses import dataclass

from src.console import console
from scapy.all import PcapReader
from scapy.layers.dot11 import Dot11Beacon, Dot11ProbeResp
from scapy.layers.eap import EAPOL_KEY

CHECK = "OK"
CROSS = "--"


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


@dataclass
class ValidationResult:
    is_valid: bool = False
    has_m1: bool = False
    has_m2: bool = False
    has_m3: bool = False
    has_m4: bool = False
    error: str | None = None
    relevant_packets: list = None

def validate_handshake(filepath: str) -> ValidationResult:
    result = ValidationResult()
    result.relevant_packets = []
    try:
        with PcapReader(filepath) as pcap:
            for pkt in pcap:
                if pkt.haslayer(EAPOL_KEY):
                    result.relevant_packets.append(pkt)
                    ek = pkt[EAPOL_KEY]
                    msg_type = _classify_eapol(ek)
                    if msg_type == "M1":
                        result.has_m1 = True
                    elif msg_type == "M2":
                        result.has_m2 = True
                    elif msg_type == "M3":
                        result.has_m3 = True
                    elif msg_type == "M4":
                        result.has_m4 = True
                elif pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
                    result.relevant_packets.append(pkt)
    except Exception as e:
        result.error = f"cannot read pcap: {e}"
        return result

    result.is_valid = result.has_m1 and result.has_m2
    return result


def _hline(widths: list[int]) -> str:
    parts = ["+"]
    for w in widths:
        parts.append("-" * (w + 2) + "+")
    return "".join(parts)


def _row(cells: list[str], widths: list[int]) -> str:
    parts = ["|"]
    for c, w in zip(cells, widths):
        parts.append(f" {c}".ljust(w + 2) + "|")
    return "".join(parts)


def validate_all_handshakes(file_list: list[str]) -> tuple[dict[str, ValidationResult], list[tuple[str, str]]]:
    if not file_list:
        return {}, []
    console.print("\nValidating handshake files... (M1 + M2 is sufficient for validity)")

    results = []
    for f in file_list:
        v = validate_handshake(f)
        results.append((f, v))

    name_width = max(len(os.path.basename(f)) for f, _ in results)
    name_width = max(name_width, 4)
    col_w = 4
    widths = [name_width, col_w, col_w, col_w, col_w, 6]

    header = ["File", "M1", "M2", "M3", "M4", "Status"]
    rows = []
    valid = {}
    invalid = []

    for f, v in results:
        basename = os.path.basename(f)
        if v.error:
            cells = [basename, CROSS, CROSS, CROSS, CROSS, "ERROR"]
            invalid.append((f, v.error))
        else:
            cells = [
                basename,
                CHECK if v.has_m1 else CROSS,
                CHECK if v.has_m2 else CROSS,
                CHECK if v.has_m3 else CROSS,
                CHECK if v.has_m4 else CROSS,
                "VALID" if v.is_valid else "INVALID",
            ]
            if v.is_valid:
                valid[f] = v
            else:
                invalid.append((f, "missing M1 or M2"))
        rows.append(cells)

    console.print(_hline(widths))
    console.print(_row(header, widths))
    console.print(_hline(widths))
    for cells in rows:
        console.print(_row(cells, widths))
    console.print(_hline(widths))

    console.print(f"\n  {len(valid)} valid, {len(invalid)} invalid")
    return valid, invalid
