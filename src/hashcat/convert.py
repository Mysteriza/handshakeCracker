from __future__ import annotations

import os

from scapy.all import PcapReader
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeResp
from scapy.layers.eap import EAPOL, EAPOL_KEY

from src.console import log_debug, log_error
from src.validator import _classify_eapol


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
    except Exception:
        return None


def _pkt_bssid(pkt) -> str | None:
    try:
        if pkt.haslayer(Dot11):
            for attr in ("addr3", "addr2", "addr1"):
                mac = getattr(pkt[Dot11], attr, None)
                if mac and str(mac).lower() != "ff:ff:ff:ff:ff:ff":
                    return _format_mac(str(mac))
    except Exception:
        pass
    return None


def _beacon_essid(pkt) -> str | None:
    try:
        elt = pkt.getlayer(Dot11Elt)
        while elt is not None:
            try:
                if int(getattr(elt, "ID", -1)) == 0 and getattr(elt, "info", None):
                    return bytes(elt.info).decode("utf-8", errors="replace").rstrip(
                        "\x00"
                    )
            except Exception:
                pass
            nxt = elt.payload
            elt = nxt if isinstance(nxt, Dot11Elt) else None
    except Exception:
        pass
    return None


def _build_line(
    essid: str,
    ap_mac: str,
    sta_mac: str,
    frames: dict,
) -> str | None:
    if "M2" not in frames:
        return None
    m2_pkt = frames["M2"]
    m2_ek = m2_pkt[EAPOL_KEY]
    if "M1" in frames:
        try:
            anonce = bytes(frames["M1"][EAPOL_KEY].key_nonce).hex()
        except Exception:
            return None
    elif "M3" in frames:
        try:
            anonce = bytes(frames["M3"][EAPOL_KEY].key_nonce).hex()
        except Exception:
            return None
    else:
        return None
    try:
        mic = bytes(m2_ek.key_mic).hex()
    except Exception:
        return None
    eapol_raw_bytes = _extract_raw_eapol(m2_pkt)
    if eapol_raw_bytes is None:
        return None
    try:
        declared_len = 4 + int(m2_pkt[EAPOL].len)
        if len(eapol_raw_bytes) > declared_len:
            eapol_raw_bytes = eapol_raw_bytes[:declared_len]
    except Exception:
        pass
    if len(eapol_raw_bytes) < 81 + 16:
        log_error(
            "convert_cap_to_hc22000: EAPOL frame too short for MIC zeroing",
            Exception(f"len={len(eapol_raw_bytes)}"),
        )
        return None
    eapol_bytes = bytearray(eapol_raw_bytes)
    eapol_bytes[81:97] = b"\x00" * 16
    eapol_hex = bytes(eapol_bytes).hex()

    essid_out = essid or "Unknown"
    essid_hex = essid_out.encode("utf-8", errors="replace").hex()
    ap_nocolon = ap_mac.replace(":", "")
    sta_nocolon = sta_mac.replace(":", "")
    has_m3 = "M3" in frames
    has_m4 = "M4" in frames
    message_pair = "02" if (has_m3 or has_m4) else "00"
    return (
        f"WPA*02*{mic}*{ap_nocolon}*{sta_nocolon}"
        f"*{essid_hex}*{anonce}*{eapol_hex}*{message_pair}"
    )


def convert_cap_to_hc22000(
    cap_path: str, output_path: str, packets: list | None = None
) -> bool:
    log_debug(f"convert_cap_to_hc22000: reading {cap_path}")
    if packets is None:
        try:
            packets = []
            with PcapReader(cap_path) as pcap:
                for pkt in pcap:
                    if (
                        pkt.haslayer(EAPOL_KEY)
                        or pkt.haslayer(Dot11Beacon)
                        or pkt.haslayer(Dot11ProbeResp)
                    ):
                        packets.append(pkt)
        except Exception as e:
            log_error(f"Failed to read {cap_path}", e)
            return False
    log_debug(
        f"convert_cap_to_hc22000: loaded {len(packets)} relevant packet(s) from cap"
    )
    groups: dict[str, dict] = {}
    for pkt in packets:
        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            bssid = _pkt_bssid(pkt)
            if not bssid:
                continue
            g = groups.setdefault(bssid, {"frames": {}, "essid": ""})
            essid = _beacon_essid(pkt)
            if essid and not g["essid"]:
                g["essid"] = essid
            continue
        if not pkt.haslayer(EAPOL_KEY):
            continue
        msg = _classify_eapol(pkt[EAPOL_KEY])
        if not msg:
            continue
        bssid = _pkt_bssid(pkt) or "unknown"
        g = groups.setdefault(bssid, {"frames": {}, "essid": ""})
        g["frames"][msg] = pkt
        if pkt.haslayer(Dot11):
            try:
                d = pkt[Dot11]
                g.setdefault("addr1", _format_mac(str(d.addr1)))
                g.setdefault("addr2", _format_mac(str(d.addr2)))
            except Exception:
                pass

    lines: list[str] = []
    for bssid, g in groups.items():
        frames = g["frames"]
        if "M2" not in frames:
            continue
        m2_pkt = frames["M2"]
        essid = g.get("essid") or ""
        ap_mac = bssid if bssid != "unknown" else None
        sta_mac = None
        try:
            if m2_pkt.haslayer(Dot11):
                a1 = _format_mac(str(m2_pkt[Dot11].addr1))
                a2 = _format_mac(str(m2_pkt[Dot11].addr2))
                if ap_mac and a2 != ap_mac and a1 == ap_mac:
                    sta_mac = a2
                elif ap_mac and a1 != ap_mac:
                    sta_mac = a1
                else:
                    if not ap_mac:
                        ap_mac = a1
                        sta_mac = a2
                    else:
                        sta_mac = a2 if a1 == ap_mac else a1
        except Exception:
            pass
        if not ap_mac or not sta_mac:
            continue
        line = _build_line(essid, ap_mac, sta_mac, frames)
        if line:
            lines.append(line)
    log_debug(f"convert_cap_to_hc22000: built {len(lines)} hc22000 line(s)")
    if not lines:
        log_debug("convert_cap_to_hc22000: M2 not found in capture")
        return False
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        for line in lines:
            f.write(line + "\n")
    log_debug(f"convert_cap_to_hc22000: OK wrote {len(lines)} line(s) to {output_path}")
    return True
