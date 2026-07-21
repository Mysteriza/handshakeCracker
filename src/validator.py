import os

from src.console import console, colored_log, log_error
from scapy.all import rdpcap
from scapy.layers.eap import EAPOL_KEY


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


def validate_handshake(filepath: str) -> dict:
    result = {"is_valid": False, "has_m1": False, "has_m2": False, "error": None}
    try:
        packets = rdpcap(filepath)
    except Exception as e:
        result["error"] = f"cannot read pcap: {e}"
        return result

    for pkt in packets:
        if not pkt.haslayer(EAPOL_KEY):
            continue
        ek = pkt[EAPOL_KEY]
        msg_type = _classify_eapol(ek)
        if msg_type == "M1":
            result["has_m1"] = True
        elif msg_type == "M2":
            result["has_m2"] = True

    result["is_valid"] = result["has_m1"] and result["has_m2"]
    return result


def validate_all_handshakes(file_list: list[str]) -> tuple[list[str], list[tuple[str, str]]]:
    console.print("\n[cyan]Validating handshake files...[/cyan]")
    valid = []
    invalid = []

    for f in file_list:
        v = validate_handshake(f)
        if v["is_valid"]:
            valid.append(f)
            console.print(f"  [green]VALID[/green]   {os.path.basename(f)}")
        else:
            reason = v["error"] or "missing M1 or M2"
            invalid.append((f, reason))
            console.print(f"  [red]INVALID[/red] {os.path.basename(f)} - {reason}")

    console.print(
        f"\n  Summary: [green]{len(valid)} valid[/green], "
        f"[red]{len(invalid)} invalid[/red]"
    )
    return valid, invalid
