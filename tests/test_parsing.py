from src.hashcat.crack import _extract_password_from_lines
from src.hashcat.convert import _format_mac

def test_extract_password_valid():
    lines = {"WPA*02*abc123*...", "WPA*02*abc123*...:mypassword1"}
    assert _extract_password_from_lines(lines) == "mypassword1"

def test_extract_password_too_short():
    lines = {"hash:short"}   # < 8 karakter
    assert _extract_password_from_lines(lines) is None

def test_extract_password_too_long():
    lines = {"hash:" + "x" * 64}   # > 63 karakter
    assert _extract_password_from_lines(lines) is None

def test_extract_password_empty():
    assert _extract_password_from_lines(set()) is None

def test_format_mac_colon():
    assert _format_mac("AA:BB:CC:DD:EE:FF") == "aa:bb:cc:dd:ee:ff"

def test_format_mac_bytes():
    assert _format_mac(b'\xaa\xbb\xcc\xdd\xee\xff') == "aa:bb:cc:dd:ee:ff"

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
