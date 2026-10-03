from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

from scapy.all import PcapReader
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeResp
from scapy.layers.eap import EAPOL_KEY

from src.console import console

CHECK = "OK"
CROSS = "--"

_PMKID_OUI = bytes.fromhex("000fac")


def _is_zero(data: bytes) -> bool:
    return len(data) > 0 and all(b == 0 for b in data)


def _get_nonce(ek) -> bytes:
    try:
        return bytes(ek.key_nonce or b"")
    except Exception:
        return b""


def _get_mic(ek) -> bytes:
    try:
        return bytes(ek.key_mic or b"")
    except Exception:
        return b""


def _get_key_data(ek) -> bytes:
    for attr in ("key_data", "keydata", "key_information_data"):
        try:
            val = getattr(ek, attr, None)
            if val:
                return bytes(val)
        except Exception:
            continue
    return b""


def _has_pmkid_kde(ek) -> bool:
    data = _get_key_data(ek)
    if len(data) < 8:
        return False
    idx = data.find(_PMKID_OUI)
    while idx != -1:
        if (
            idx + 4 <= len(data)
            and data[idx + 3] == 0x04
            and idx + 20 <= len(data)
        ):
            return True
        idx = data.find(_PMKID_OUI, idx + 1)
    return False


def _classify_eapol(ek) -> str | None:
    try:
        ack = bool(ek.key_ack)
        mic_flag = bool(ek.has_key_mic)
        ins = bool(ek.install)
        sec = bool(ek.secure)
        ver = int(getattr(ek, "key_descriptor_type_version", 0) or 0)
    except Exception:
        return None
    if ver not in (0, 1, 2, 3):
        return None
    nonce = _get_nonce(ek)
    mic = _get_mic(ek)
    if nonce and _is_zero(nonce):
        return None
    if ack and not mic_flag and not ins and not sec:
        if mic and not _is_zero(mic):
            return None
        return "M1"
    if not ack and mic_flag and not ins and not sec:
        if not mic or _is_zero(mic):
            return None
        return "M2"
    if ack and mic_flag and ins and sec:
        if not mic or _is_zero(mic):
            return None
        return "M3"
    if not ack and mic_flag and not ins and sec:
        if not mic or _is_zero(mic):
            return None
        return "M4"
    return None


def _extract_essid(pkt) -> str | None:
    try:
        elt = pkt.getlayer(Dot11Elt)
        while elt is not None:
            try:
                if int(getattr(elt, "ID", -1)) == 0 and getattr(elt, "info", None):
                    raw = bytes(elt.info)
                    return raw.decode("utf-8", errors="replace").rstrip("\x00")
            except Exception:
                pass
            nxt = elt.payload
            elt = nxt if isinstance(nxt, Dot11Elt) else None
    except Exception:
        pass
    return None


def _pkt_bssid(pkt) -> str | None:
    try:
        if pkt.haslayer(Dot11):
            for attr in ("addr3", "addr2", "addr1"):
                mac = getattr(pkt[Dot11], attr, None)
                if mac and str(mac).lower() != "ff:ff:ff:ff:ff:ff":
                    return str(mac).lower()
    except Exception:
        pass
    return None


@dataclass
class ValidationResult:
    is_valid: bool = False
    has_pmkid: bool = False
    has_m1: bool = False
    has_m2: bool = False
    has_m3: bool = False
    has_m4: bool = False
    error: str | None = None
    relevant_packets: list[Any] = field(default_factory=list)
    bssid: str | None = None
    essid: str | None = None
    networks: dict[str, dict[str, Any]] = field(default_factory=dict)


def validate_handshake(filepath: str) -> ValidationResult:
    result = ValidationResult()
    try:
        if filepath.lower().endswith(".hc22000"):
            with open(filepath, encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("WPA*01*"):
                        result.has_pmkid = True
                    elif line.startswith("WPA*02*"):
                        result.has_m1 = True
                        result.has_m2 = True
        else:
            networks: dict[str, dict[str, Any]] = {}
            with PcapReader(filepath) as pcap:
                for pkt in pcap:
                    if pkt.haslayer(EAPOL_KEY):
                        ek = pkt[EAPOL_KEY]
                        if _has_pmkid_kde(ek):
                            result.has_pmkid = True
                        msg_type = _classify_eapol(ek)
                        bssid = _pkt_bssid(pkt)
                        key = bssid or "unknown"
                        net = networks.setdefault(
                            key, {"frames": {}, "essid": None, "pmkid": False}
                        )
                        if _has_pmkid_kde(ek):
                            net["pmkid"] = True
                        if msg_type:
                            net["frames"][msg_type] = pkt
                            result.relevant_packets.append(pkt)
                            if msg_type == "M1":
                                result.has_m1 = True
                            elif msg_type == "M2":
                                result.has_m2 = True
                            elif msg_type == "M3":
                                result.has_m3 = True
                            elif msg_type == "M4":
                                result.has_m4 = True
                    elif pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
                        essid = _extract_essid(pkt)
                        bssid = _pkt_bssid(pkt)
                        if bssid:
                            net = networks.setdefault(
                                bssid, {"frames": {}, "essid": None, "pmkid": False}
                            )
                            if essid and not net["essid"]:
                                net["essid"] = essid
                        if len(result.relevant_packets) < 4 and pkt.haslayer(
                            Dot11Beacon
                        ):
                            result.relevant_packets.append(pkt)
            result.networks = networks
            if networks:
                best_key = max(
                    networks.keys(),
                    key=lambda k: (
                        "M2" in networks[k]["frames"],
                        networks[k]["pmkid"],
                        len(networks[k]["frames"]),
                    ),
                )
                best = networks[best_key]
                result.bssid = None if best_key == "unknown" else best_key
                result.essid = best.get("essid")
    except Exception as e:
        result.error = f"cannot read file: {e}"
        return result

    result.is_valid = (result.has_m1 and result.has_m2) or result.has_pmkid
    return result


def _hline(widths: list[int]) -> str:
    parts = ["+"]
    for w in widths:
        parts.append("-" * (w + 2) + "+")
    return "".join(parts)


def _row(cells: list[str], widths: list[int]) -> str:
    parts = ["|"]
    for c, w in zip(cells, widths, strict=False):
        parts.append(f" {c}".ljust(w + 2) + "|")
    return "".join(parts)


def validate_all_handshakes(
    file_list: list[str],
) -> tuple[dict[str, ValidationResult], list[tuple[str, str]]]:
    if not file_list:
        return {}, []
    console.print(
        "\nValidating handshake files... (M1+M2 or PMKID is sufficient for validity)"
    )

    results = []
    for f in file_list:
        v = validate_handshake(f)
        results.append((f, v))

    name_width = max(len(os.path.basename(f)) for f, _ in results)
    name_width = max(name_width, 4)
    col_w = 4
    col_pmkid = 5
    widths = [name_width, col_pmkid, col_w, col_w, col_w, col_w, 6]

    header = ["File", "PMKID", "M1", "M2", "M3", "M4", "Status"]
    rows = []
    valid = {}
    invalid = []

    for f, v in results:
        basename = os.path.basename(f)
        if v.error:
            cells = [basename, CROSS, CROSS, CROSS, CROSS, CROSS, "ERROR"]
            invalid.append((f, v.error))
        else:
            cells = [
                basename,
                CHECK if v.has_pmkid else CROSS,
                CHECK if v.has_m1 else CROSS,
                CHECK if v.has_m2 else CROSS,
                CHECK if v.has_m3 else CROSS,
                CHECK if v.has_m4 else CROSS,
                "VALID" if v.is_valid else "INVALID",
            ]
            if v.is_valid:
                valid[f] = v
            else:
                invalid.append((f, "missing M1/M2 or PMKID"))
        rows.append(cells)

    console.print(_hline(widths))
    console.print(_row(header, widths))
    console.print(_hline(widths))
    for cells in rows:
        console.print(_row(cells, widths))
    console.print(_hline(widths))

    console.print(f"\n  {len(valid)} valid, {len(invalid)} invalid")
    return valid, invalid
