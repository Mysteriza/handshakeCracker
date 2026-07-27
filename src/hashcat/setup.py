import os
import sys
import time
import tempfile
import platform
import subprocess
from src.console import console, colored_log, log_error, log_debug
from src.config import BIN_DIR, HASHCAT_VERSION, HASHCAT_URL, HCOV_DIR, DEPS_DIR, HASHCAT_ARCHIVE_NAME, HASHCAT_SHA256
from src.utils import download_with_progress
_SYSTEM = platform.system()

_hashcat_path_cache = None

def _find_in_path(name: str) -> str | None:
    for d in os.environ.get('PATH', '').split(os.pathsep):
        p = os.path.join(d.strip('"'), name)
        if os.path.isfile(p):
            return p
    return None

def _get_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def get_hashcat_path() -> str | None:
    global _hashcat_path_cache
    if _hashcat_path_cache:
        return _hashcat_path_cache
    exe = 'hashcat.exe' if _SYSTEM == 'Windows' else 'hashcat'
    found = _find_in_path(exe)
    if found:
        log_debug(f'get_hashcat_path: found in PATH: {found}')
        _hashcat_path_cache = found
        return found
    root = _get_root()
    local = os.path.join(root, BIN_DIR, f'hashcat-{HASHCAT_VERSION}', exe)
    if os.path.isfile(local):
        log_debug(f'get_hashcat_path: found locally: {local}')
        _hashcat_path_cache = local
        return local
    log_debug(f'get_hashcat_path: not found (checked PATH and {local})')
    return None

def _extract_archive(archive: str, dest: str) -> bool:
    if not os.path.isfile(archive):
        log_error(f'_extract_archive: archive not found: {archive}')
        return False
    log_debug(f'_extract_archive: archive={archive} dest={dest}')
    extractor_name = '7z'
    try:
        if _SYSTEM == 'Windows':
            sz = os.path.join(dest, '7zr.exe')
            if not os.path.isfile(sz):
                colored_log('info', 'Downloading 7-Zip standalone extractor...')
                log_debug('_extract_archive: downloading 7zr.exe')

                download_with_progress('https://www.7-zip.org/a/7zr.exe', sz, 'Downloading 7zr')
            extractor = [sz, 'x', archive, f'-o{dest}', '-y']
            extractor_name = '7zr'
        else:
            extractor = ['7z', 'x', archive, f'-o{dest}', '-y']
        log_debug(f'_extract_archive: extracting with {extractor[0]} from {archive}')
        r = subprocess.run(extractor, capture_output=True, text=True, timeout=120)
        ok = r.returncode == 0
        log_debug(f'_extract_archive: {extractor[0]} exit code={r.returncode} ok={ok}')
        if not ok:
            log_debug(f'_extract_archive: {extractor[0]} stderr', r.stderr[:500])
        return ok
    except FileNotFoundError:
        log_error('7z not found. Install it: sudo apt-get install p7zip-full  (or  brew install p7zip on macOS)')
        return False
    except Exception as e:
        log_debug(f'_extract_archive: {extractor_name} exception', str(e))
        return False

def ensure_hashcat() -> bool:
    found = get_hashcat_path()
    log_debug(f'ensure_hashcat: get_hashcat_path() returned {found!r}')
    if found:
        log_debug('ensure_hashcat: hashcat already available')
        return True
    root = _get_root()
    dest_dir = os.path.join(root, BIN_DIR)
    os.makedirs(dest_dir, exist_ok=True)
    tmp_path = None
    try:
        local_archive = os.path.join(root, DEPS_DIR, HASHCAT_ARCHIVE_NAME)
        log_debug(f'ensure_hashcat: checking local archive: {local_archive} exists={os.path.isfile(local_archive)}')
        if os.path.isfile(local_archive):
            colored_log('info', 'Found local hashcat archive, extracting...')
            ok = _extract_archive(local_archive, dest_dir)
            log_debug(f'ensure_hashcat: local extraction result={ok}')
            if ok and get_hashcat_path():
                colored_log('success', f'hashcat {HASHCAT_VERSION} ready.')
                return True
            colored_log('warning', 'Local hashcat extraction failed — trying download.')
        log_debug(f'ensure_hashcat: downloading from {HASHCAT_URL}')
        tmp = tempfile.NamedTemporaryFile(suffix='.7z', delete=False)
        tmp_path = tmp.name
        tmp.close()
        log_debug(f'ensure_hashcat: temp download path: {tmp_path}')
        if not download_with_progress(HASHCAT_URL, tmp_path, 'Downloading hashcat', HASHCAT_SHA256):
            log_error('ensure_hashcat: download failed')
            return False
        log_debug('ensure_hashcat: download OK, extracting')
        colored_log('info', 'Extracting hashcat...')
        if _extract_archive(tmp_path, dest_dir):
            if get_hashcat_path():
                colored_log('success', f'hashcat {HASHCAT_VERSION} ready.')
                return True
        colored_log('error', 'hashcat extraction failed.')
        return False
    except KeyboardInterrupt:
        colored_log('warning', 'Hashcat setup interrupted by user.')
        return False
    except Exception as e:
        log_error('Failed to download/extract hashcat', e)
        return False
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
                log_debug('ensure_hashcat: cleaned up temp file')
            except OSError:
                pass

def _kernel_cache_exists(hc_dir: str) -> bool:
    """Check if Hashcat has compiled kernel binaries for mode 22000 already."""
    kernels_dir = os.path.join(hc_dir, 'kernels')
    if not os.path.isdir(kernels_dir):
        return False
    for fname in os.listdir(kernels_dir):
        if fname.endswith('.kernel') or fname.endswith('.bin'):
            return True
    return False

def warmup_hashcat_kernel(hc22000_path: str | None=None) -> bool:
    """Pre-compile GPU kernel for mode 22000 using the real handshake hash.

    Requires a valid *hc22000_path* to a converted .hc22000 file — no
    synthetic/dummy hashes are used (see Testing Policy in AGENTS.md).
    """
    hc_exe = get_hashcat_path()
    if not hc_exe:
        return False
    hc_dir = os.path.dirname(hc_exe)
    if _kernel_cache_exists(hc_dir):
        log_debug('warmup_hashcat_kernel: kernel cache found, skipping compilation')
        colored_log('info', 'GPU kernel cache found — compilation not required.')
        return True
    if not hc22000_path or not os.path.isfile(hc22000_path):
        log_debug('warmup_hashcat_kernel: no real hash file available, skipping warmup')
        return False
    os.makedirs(HCOV_DIR, exist_ok=True)
    warmup_hash = os.path.abspath(hc22000_path)
    dummy_wordlist = os.path.abspath(os.path.join(HCOV_DIR, '_warmup_wl.txt'))
    cleanup_files: list[str] = [dummy_wordlist]
    log_debug(f'warmup_hashcat_kernel: using real hash: {hc22000_path}')
    with open(dummy_wordlist, 'w') as f:
        f.write('testpassword\n')
    potfile = os.path.abspath(os.path.join(HCOV_DIR, '_warmup.potfile'))
    cmd = [hc_exe, '-m', '22000', '-a', '0', '-w', '1', '--potfile-path', potfile, warmup_hash, dummy_wordlist]
    cleanup_files.append(potfile)
    try:
        log_debug('warmup_hashcat_kernel: no kernel cache found, running first-time compilation')
        console.rule('[bold yellow]GPU Kernel Compilation (First Run)[/bold yellow]', style='yellow')
        colored_log('info', 'Compiling GPU kernel for WPA/WPA2 cracking...')
        console.print('  [dim]This one-time step prepares your GPU for faster cracking.[/dim]')
        console.print('  [dim]Time: ~30–90 seconds depending on GPU and driver.[/dim]')
        console.print('')
        start = time.time()
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding='utf-8', errors='replace', cwd=hc_dir)
        if proc.stdout is None:
            raise RuntimeError('stdout pipe not created')
        output_lines: list[str] = []
        device_name = ''
        import threading
        _spin_stop = threading.Event()

        def _spin():
            chars = ['-', '\\', '|', '/']
            c = 0
            while not _spin_stop.is_set():
                sys.stdout.write(f'\r  {chars[c % 4]} Compiling GPU kernel...')
                sys.stdout.flush()
                c += 1
                time.sleep(0.25)
        spin_thread = threading.Thread(target=_spin, daemon=True)
        spin_thread.start()
        for line in proc.stdout:
            line_str = line.rstrip('\n\r')
            output_lines.append(line_str)
            if line_str.startswith('* Device #'):
                device_name = line_str.split(',')[0].replace('* Device #1: ', '').strip()
        try:
            proc.wait(timeout=300)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            log_debug('warmup_hashcat_kernel: timed out after 300s, process killed')
            colored_log('warning', 'GPU kernel compilation timed out (>5 min). Skipping warmup.')
            return False
        finally:
            _spin_stop.set()
            spin_thread.join(timeout=2)
            sys.stdout.write('\r' + ' ' * 40 + '\r')
            sys.stdout.flush()
        elapsed = time.time() - start
        log_debug(f'warmup_hashcat_kernel: finished in {elapsed:.2f}s (rc={proc.returncode})')
        console.print('')
        kernel_cached = _kernel_cache_exists(hc_dir)
        if kernel_cached:
            colored_log('success', f"GPU kernel ready{(' on ' + device_name if device_name else '')} ({int(elapsed)}s). Cached for next run.")
        else:
            colored_log('warning', 'GPU kernel compilation skipped — will use hashcat with default kernels.')
        console.rule(style='yellow')
        return kernel_cached
    except Exception as e:
        log_debug(f'warmup_hashcat_kernel: failed ({e})')
        return False
    finally:
        for f in cleanup_files:
            if os.path.exists(f):
                try:
                    os.remove(f)
                except OSError:
                    pass

def add_bin_to_path():
    hc = get_hashcat_path()
    if hc:
        parent = os.path.dirname(hc)
        if parent not in os.environ.get('PATH', ''):
            old = os.environ.get('PATH', '')
            os.environ['PATH'] = parent + os.pathsep + old
            log_debug(f'add_bin_to_path: prepended {parent} to PATH')
        else:
            log_debug(f'add_bin_to_path: {parent} already in PATH')
    else:
        log_debug('add_bin_to_path: hashcat not found, nothing to add')
