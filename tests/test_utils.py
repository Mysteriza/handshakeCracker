
from src.utils import sanitize_ssid, strip_capture_extension

def test_sanitize_ssid():
    assert sanitize_ssid("My Network!") == "My_Network!"
    assert sanitize_ssid("hello world") == "hello_world"
    assert sanitize_ssid("SSID<123>") == "SSID123"

def test_strip_capture_extension():
    assert strip_capture_extension("capture.cap") == "capture"
    assert strip_capture_extension("capture.pcap") == "capture"
    assert strip_capture_extension("capture.txt") == "capture.txt"
    assert strip_capture_extension("/path/to/capture.pcapng") == "capture.pcapng"

def test_strip_capture_extension_with_cap_in_name():
    """Nama file yang mengandung '.cap' sebagai substring — bukan hanya ekstensi."""
    assert strip_capture_extension("Home.cap_backup.cap") == "Home.cap_backup"
    assert strip_capture_extension("router.capture.pcap") == "router.capture"

def test_sanitize_ssid_special_chars():
    assert sanitize_ssid('Net/work') == 'Network'
    assert sanitize_ssid('  spaces  ') == 'spaces'
    assert sanitize_ssid('name:value') == 'namevalue'
