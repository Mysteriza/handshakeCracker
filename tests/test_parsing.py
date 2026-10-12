from types import SimpleNamespace

from src.hashcat.convert import _format_mac, _m2_version_supported
from src.hashcat.crack import (
    _extract_password_from_lines,
    _parse_show_output,
)
from src.validator import _classify_eapol


def _ek(**kw):
    base = dict(
        key_ack=0,
        has_key_mic=0,
        install=0,
        secure=0,
        key_descriptor_type_version=2,
        key_nonce=b"\x01" * 32,
        key_mic=b"\x02" * 16,
        key_data=b"",
    )
    base.update(kw)
    return SimpleNamespace(**base)


def test_extract_password_valid():
    lines = {"WPA*02*abc123*...", "WPA*02*abc123*...:mypassword1"}
    assert _extract_password_from_lines(lines) == "mypassword1"


def test_extract_password_too_short():
    lines = {"hash:short"}  # < 8 karakter
    assert _extract_password_from_lines(lines) is None


def test_extract_password_too_long():
    lines = {"hash:" + "x" * 64}  # > 63 karakter
    assert _extract_password_from_lines(lines) is None


def test_extract_password_empty():
    assert _extract_password_from_lines(set()) is None


def test_format_mac_colon():
    assert _format_mac("AA:BB:CC:DD:EE:FF") == "aa:bb:cc:dd:ee:ff"


def test_format_mac_bytes():
    assert _format_mac(b"\xaa\xbb\xcc\xdd\xee\xff") == "aa:bb:cc:dd:ee:ff"


def test_format_mac_invalid():
    assert _format_mac("invalid") == "00:00:00:00:00:00"


def test_format_mac_dash_format():
    assert _format_mac("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff"


def test_format_mac_no_separator():
    assert _format_mac("aabbccddeeff") == "aa:bb:cc:dd:ee:ff"


def test_extract_password_boundary_8_chars():
    lines = {"hash:12345678"}
    assert _extract_password_from_lines(lines) == "12345678"


def test_extract_password_boundary_63_chars():
    lines = {"hash:" + "x" * 63}
    assert _extract_password_from_lines(lines) == "x" * 63


def test_parse_show_output_hit():
    out = "1f16665656837e2a4e391638570e89c4:68f543f3a778:b0dcef8f670e:Kosan bu nata:mypassword1\n"
    assert _parse_show_output(out) == "mypassword1"


def test_parse_show_output_real_22000_format():
    out = "1f16665656837e2a4e391638570e89c4:68f543f3a778:b0dcef8f670e:Kosan bu nata:immodium\n"
    assert _parse_show_output(out) == "immodium"


def test_parse_show_output_empty():
    assert _parse_show_output("") is None
    assert _parse_show_output("  \n# comment\n") is None


def test_parse_show_output_bad_lengths():
    assert _parse_show_output("WPA*02*x:short\n") is None
    assert _parse_show_output("WPA*02*x:" + "y" * 64 + "\n") is None


def test_parse_show_output_rejects_salt_value_exception():
    out = (
        "Hashfile 'D:\\handshakeCracker\\hc22000_cache\\HS_1617515BF578_OPPO_Reno14_F_5G_b846.hc22000' "
        "on line 1 (WPA*02...969172136bbd9dc3f628e99869f01*02): Salt-value exception\n"
        "No hashes loaded.\n"
    )
    assert _parse_show_output(out) is None


def test_parse_show_output_rejects_non_hex_prefix():
    out = "nothex:68f543f3a778:b0dcef8f670e:Some ESSID:somepassword1\n"
    assert _parse_show_output(out) is None


def test_extract_password_rejects_error_text():
    lines = {"WPA*02*8904be9b:Salt-value exception"}
    assert _extract_password_from_lines(lines) is None


def test_m2_version_support():
    assert _m2_version_supported(_ek(key_descriptor_type_version=2)) is True
    assert _m2_version_supported(_ek(key_descriptor_type_version=1)) is True
    assert _m2_version_supported(_ek(key_descriptor_type_version=3)) is True
    assert _m2_version_supported(_ek(key_descriptor_type_version=0)) is False


def test_classify_m4_allows_zero_nonce():
    m4 = _ek(has_key_mic=1, secure=1, key_nonce=b"\x00" * 32)
    assert _classify_eapol(m4) == "M4"


def test_classify_m4_rejects_zero_mic():
    m4 = _ek(has_key_mic=1, secure=1, key_mic=b"\x00" * 16)
    assert _classify_eapol(m4) is None


def test_classify_m2_version_zero_still_m2():
    m2 = _ek(has_key_mic=1, key_descriptor_type_version=0)
    assert _classify_eapol(m2) == "M2"
