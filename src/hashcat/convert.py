import os
import platform
from scapy.all import PcapReader
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeResp
from scapy.layers.eap import EAPOL, EAPOL_KEY
from src.console import log_error, log_debug
from src.validator import _classify_eapol
_SYSTEM = platform.system()


def _format_mac(mac) -> str:
    if isinstance(mac, str):
        mac = mac.replace('-', ':').replace(' ', '')
        parts = mac.split(':')
        if len(parts) == 6:
            return ':'.join((f'{p.lower():0>2s}' for p in parts))
        mac = mac.replace(':', '')
        try:
            b = bytes.fromhex(mac)
            return ':'.join((f'{x:02x}' for x in b))
        except ValueError:
            return '00:00:00:00:00:00'
    if isinstance(mac, bytes):
        if len(mac) == 6:
            return ':'.join((f'{x:02x}' for x in mac))
        return '00:00:00:00:00:00'
    return '00:00:00:00:00:00'

def _extract_raw_eapol(pkt) -> bytes | None:
    try:
        return bytes(pkt[EAPOL])
    except Exception:
        return None

def convert_cap_to_hc22000(cap_path: str, output_path: str, packets: list | None=None) -> bool:
    log_debug(f'convert_cap_to_hc22000: reading {cap_path}')
    if packets is None:
        try:
            packets = []
            with PcapReader(cap_path) as pcap:
                for pkt in pcap:
                    if pkt.haslayer(EAPOL_KEY) or pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
                        packets.append(pkt)
        except Exception as e:
            log_error(f'Failed to read {cap_path}', e)
            return False
    log_debug(f'convert_cap_to_hc22000: loaded {len(packets)} relevant packet(s) from cap')
    essid = ''
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
    log_debug(f'convert_cap_to_hc22000: beacons={beacon_count} EAPOL frames found={list(frames.keys())}')
    if 'M2' not in frames:
        log_debug('convert_cap_to_hc22000: M2 not found in capture')
        return False
    m2_pkt = frames['M2']
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
    if 'M1' in frames:
        anonce = bytes(frames['M1'][EAPOL_KEY].key_nonce).hex()
        if not ap_mac and frames['M1'].haslayer(Dot11):
            ap_mac = _format_mac(frames['M1'][Dot11].addr2)
    elif 'M3' in frames:
        anonce = bytes(frames['M3'][EAPOL_KEY].key_nonce).hex()
    snonce = bytes(m2_ek.key_nonce).hex()
    mic = bytes(m2_ek.key_mic).hex()
    key_ver = m2_ek.key_descriptor_type_version
    eapol_raw_bytes = _extract_raw_eapol(m2_pkt)
    if eapol_raw_bytes is None:
        log_debug('convert_cap_to_hc22000: failed to extract raw EAPOL bytes from M2')
        return False
    declared_len = 4 + m2_pkt[EAPOL].len
    if eapol_raw_bytes is not None and len(eapol_raw_bytes) > declared_len:
        log_debug(f'convert_cap_to_hc22000: trimming EAPOL from {len(eapol_raw_bytes)} to {declared_len} (body len {m2_pkt[EAPOL].len})')
        eapol_raw_bytes = eapol_raw_bytes[:declared_len]
    log_debug(f'convert_cap_to_hc22000: extracted ap_mac={ap_mac} sta_mac={sta_mac}')
    log_debug(f"convert_cap_to_hc22000: anonce_len={len(anonce or '')} snonce_len={len(snonce or '')} mic_len={len(mic or '')} key_ver={key_ver}")
    log_debug(f"convert_cap_to_hc22000: eapol_raw_bytes_len={len(eapol_raw_bytes or b'')}")
    if not all([ap_mac, sta_mac, anonce, snonce, mic, key_ver]):
        log_debug(f'convert_cap_to_hc22000: validation failed - missing fields: ap={bool(ap_mac)} sta={bool(sta_mac)} anonce={bool(anonce)} snonce={bool(snonce)} mic={bool(mic)} kv={bool(key_ver)}')
        return False

    if not essid:
        essid = 'Unknown'
    essid_hex = essid.encode('utf-8', errors='replace').hex()
    if len(eapol_raw_bytes) < 81 + 16:
        log_error('convert_cap_to_hc22000: EAPOL frame too short for MIC zeroing', Exception(f'len={len(eapol_raw_bytes)}'))
        return False
    eapol_bytes = bytearray(eapol_raw_bytes)
    orig_mic = bytes(eapol_bytes[81:97]).hex()
    eapol_bytes[81:97] = b'\x00' * 16
    eapol_hex = bytes(eapol_bytes).hex()
    log_debug(f'convert_cap_to_hc22000: zeroed MIC in EAPOL frame original_mic_start={orig_mic[:16]}...')

    ap_mac_no_colon = ap_mac.replace(':', '')
    sta_mac_no_colon = sta_mac.replace(':', '')
    has_m3 = 'M3' in frames
    has_m4 = 'M4' in frames
    message_pair = '02' if (has_m3 or has_m4) else '00'
    line = f'WPA*02*{mic}*{ap_mac_no_colon}*{sta_mac_no_colon}*{essid_hex}*{anonce}*{eapol_hex}*{message_pair}'
    log_debug(f'convert_cap_to_hc22000: writing hc22000 file to {output_path}')
    os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
    with open(output_path, 'w') as f:
        f.write(line + '\n')
    log_debug(f'convert_cap_to_hc22000: OK essid={essid!r} ap={ap_mac_no_colon} sta={sta_mac_no_colon} anonce_len={len(anonce)} eapol_len={len(eapol_hex)}')
    return True
