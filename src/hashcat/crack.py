from .setup import get_hashcat_path, ensure_hashcat, add_bin_to_path, warmup_hashcat_kernel
from .convert import convert_cap_to_hc22000
import os
import sys
import time
import platform
import subprocess
from src.console import console, colored_log, log_error, log_debug
from src.config import HCOV_DIR, RESULTS_DIR
from src.utils import sanitize_ssid, strip_capture_extension, lower_process_priority
_SYSTEM = platform.system()
HASHCAT_EXHAUSTED = '__HASHCAT_EXHAUSTED__'


def _extract_password_from_lines(lines: set[str]) -> str | None:
    for pot_line in lines:
        if ':' in pot_line and (not pot_line.startswith('#')):
            pw_candidate = pot_line[pot_line.rfind(':') + 1:].strip()
            if 8 <= len(pw_candidate) <= 63:
                return pw_candidate
    return None

def _read_potfile(path: str) -> set[str]:
    if not os.path.exists(path):
        return set()
    try:
        with open(path, encoding='utf-8', errors='replace') as f:
            return set(f.read().splitlines())
    except Exception:
        return set()

def _line_is_noise(line: str) -> bool:
    """Return True if a hashcat status line should be filtered from user display."""
    if not line:
        return True
    if line.startswith('WPA*02*') or line.startswith('$WPAPSK$'):
        return True
    noise_prefixes = ['Session..........:', 'Status...........:', 'Hash.Target......:', 'Time.Started.....:', 'Time.Estimated...:', 'Speed.Chars/sec..:', 'Speed.Dev.#', 'Speed.GPU.#', 'Progress.........:', 'Restore.Point....:', 'Restore.Subsec...:', 'Candidate.Engine.:', 'Candidates.......:', 'HWMon.GPU.#', 'HWMon.Dev.#', 'Started.........:', 'Stopped.........:', 'Input.Mode......:', 'Watchdog........:', '[s]tatus', '[p]ause', '[b]ypass', '[c]heckpoint', '[q]uit', 'The password was found', 'Password found on device']
    return any((line.startswith(p) for p in noise_prefixes))

def _log_hashcat_output(heading: str, lines: list[str]):
    log_debug(f"=== {heading} ===")
    for line in lines:
        if line.strip():
            log_debug(f"  {line}")

def crack_with_hashcat(hc22000_path: str, wordlist_path: str, display_essid: str, gpu_is_discrete: bool=False) -> str | None:
    start_time = time.time()
    hc_exe = get_hashcat_path()
    log_debug(f'crack_with_hashcat: start hc_exe={hc_exe!r} hc22000={hc22000_path} wordlist={wordlist_path}')
    if not hc_exe:
        log_error('crack_with_hashcat: hashcat binary not found')
        return None
    hc_dir = os.path.dirname(hc_exe)
    os.makedirs(HCOV_DIR, exist_ok=True)
    potfile = os.path.join(HCOV_DIR, 'hashcat.potfile')
    log_debug(f'crack_with_hashcat: potfile={potfile} hc_dir={hc_dir}')
    debug_log = os.path.join(HCOV_DIR, 'hashcat_debug.log')
    try:
        if os.path.exists(debug_log):
            os.remove(debug_log)
    except OSError:
        pass
    _log_hashcat_output('DIAG', [f'Hashcat EXE: {hc_exe}', f'hc22000: {hc22000_path}', f'wordlist: {wordlist_path}', f'CWD: {hc_dir}'])
    try:
        with open(hc22000_path, 'r') as _f:
            content = _f.read().strip()
        _log_hashcat_output('HC22000 content', [content[:300]])
        log_debug(f'crack_with_hashcat: hc22000 file length={len(content)} starts_with={content[:80]}')
    except Exception as e:
        log_error('Failed to read hc22000 file', e)
        return None

    log_debug('crack_with_hashcat: killing any lingering hashcat process')
    try:
        if _SYSTEM == 'Windows':
            subprocess.run(['taskkill', '/f', '/im', 'hashcat.exe'], capture_output=True, timeout=10)
        else:
            subprocess.run(['pkill', '-9', '-x', 'hashcat'], capture_output=True, timeout=10)
    except Exception:
        pass
    workload = '4' if gpu_is_discrete else '2'
    cmd = [hc_exe, '-m', '22000', '-a', '0', '-w', workload]
    if gpu_is_discrete:
        cmd.append('-O')
    cmd.extend(['--session', sanitize_ssid(display_essid), '--potfile-path', potfile, hc22000_path, wordlist_path])
    cmd_str = ' '.join(cmd)
    _log_hashcat_output('COMMAND', [cmd_str])
    log_debug(f'crack_with_hashcat: running command: {cmd_str}')
    potfile_before = _read_potfile(potfile)
    log_debug(f'crack_with_hashcat: potfile had {len(potfile_before)} entries before cracking')
    from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
    messages = [f'Cracking {display_essid}... Initializing kernels', f'Cracking {display_essid}... Running', f'Cracking {display_essid}... Testing candidates', f'Cracking {display_essid}... Almost there']
    progress = Progress(SpinnerColumn(spinner_name='dots12', style='cyan'), TextColumn('[progress.description]{task.description}'), TimeElapsedColumn(), console=console, transient=True)
    proc = None
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding='utf-8', errors='replace', cwd=hc_dir)
        assert proc.stdout is not None, 'stdout pipe not created'
        log_debug(f'crack_with_hashcat: subprocess started pid={proc.pid}')
        hashcat_output: list[str] = []
        line_count = 0
        kernel_init_done = False
        with progress:
            task = progress.add_task(f'[cyan]{messages[0]}', total=None)
            msg_idx = 0
            last_msg_switch = time.time()
            for raw_line in proc.stdout:
                line = raw_line.rstrip()
                line_count += 1
                hashcat_output.append(line)
                now = time.time()
                if now - last_msg_switch >= 8:
                    msg_idx = (msg_idx + 1) % len(messages)
                    last_msg_switch = now
                    progress.update(task, description=f'[cyan]{messages[msg_idx]}')
                if not kernel_init_done and line and (not line.startswith('WPA*02*')):
                    kernel_init_done = True
                    progress.update(task, description=f'[cyan]{messages[1]}')
                    try:
                        lower_process_priority(proc.pid)
                        log_debug('crack_with_hashcat: kernel init done, lowered process priority')
                    except Exception as e:
                        log_debug('crack_with_hashcat: failed to set priority', str(e))
        proc.wait()
        hashcat_output.append(f'[PROCESS EXIT CODE: {proc.returncode}]')
        _log_hashcat_output('HASHCAT OUTPUT', hashcat_output)
        log_debug(f'crack_with_hashcat: process exited rc={proc.returncode} total_lines={line_count}')
        password = None
        potfile_after = _read_potfile(potfile)
        if potfile_after:
            _log_hashcat_output('POTFILE', [f'{len(potfile_after)} entries total'])
            log_debug(f'crack_with_hashcat: potfile entries: {len(potfile_after)} total, {len(potfile_before)} before')
            new_entries = potfile_after - potfile_before
            log_debug(f'crack_with_hashcat: new potfile entries: {len(new_entries)}')
            password = _extract_password_from_lines(new_entries)
            if password:
                log_debug(f'crack_with_hashcat: password from new potfile entry: {password!r}')
            if not password and (not potfile_before):
                password = _extract_password_from_lines(potfile_after)
                if password:
                    log_debug(f'crack_with_hashcat: password from potfile (fallback): {password!r}')
                else:
                    log_debug('crack_with_hashcat: no new potfile entries and potfile had pre-existing data — password not found')
        else:
            log_debug('crack_with_hashcat: potfile is empty or does not exist')
        if password:
            elapsed = time.time() - start_time
            m, s = divmod(int(elapsed), 60)
            time_str = f'{m:02d}:{s:02d}'
            log_debug(f'crack_with_hashcat: FOUND password={password!r} time={time_str}')
            console.print(f'  Password: {password}')
            console.print(f'  Time: {time_str}')
            os.makedirs(RESULTS_DIR, exist_ok=True)
            safe_essid = sanitize_ssid(display_essid)
            result_file = os.path.join(RESULTS_DIR, f'{safe_essid}_cracked_password.txt')
            with open(result_file, 'w') as f:
                f.write(f'Network (ESSID): {display_essid}\n')
                f.write(f'Wordlist Used: {os.path.basename(wordlist_path)}\n')
                f.write(f'Password Found: {password}\n')
                f.write(f'Time Taken: {time_str}\n')
            if sys.platform != 'win32':
                try:
                    os.chmod(result_file, 0o600)
                except OSError:
                    pass
            console.print(f'  Saved to: {result_file}')
            return password
        if proc.returncode not in (0, 1):
            log_debug(f'crack_with_hashcat: hashcat exited with unexpected rc={proc.returncode}')
            _log_hashcat_output('RESULT', ['Hashcat FAILED (crash/error)'])
            log_debug('crack_with_hashcat: returning None (hashcat crashed/failed)')
            return None
        _log_hashcat_output('RESULT', ['No password found'])
        log_debug('crack_with_hashcat: returning HASHCAT_EXHAUSTED (password not found)')
        return HASHCAT_EXHAUSTED
    except FileNotFoundError as e:
        _log_hashcat_output('CRASH', [f'FileNotFoundError: {e}'])
        log_error('hashcat binary not found at path', e)
        return None
    except KeyboardInterrupt:
        if proc:
            try:
                proc.terminate()
            except Exception:
                pass
        colored_log('warning', 'Hashcat cracking interrupted by user.')
        return HASHCAT_EXHAUSTED
    except Exception as e:
        if proc:
            try:
                proc.terminate()
            except Exception:
                pass
        log_error('Hashcat execution failed', e)
        return None

def hashcat_crack_handshake(handshake_path: str, wordlist_path: str, display_essid: str, gpu_is_discrete: bool=False, packets: list | None=None) -> str | None:
    log_debug(f'hashcat_crack_handshake: start handshake={handshake_path} wordlist={wordlist_path} essid={display_essid!r}')
    hc_exe = get_hashcat_path()
    if not hc_exe:
        log_debug('hashcat_crack_handshake: hashcat path not cached, aborting')
        return None
    colored_log('info', 'Converting .cap to hashcat format (hc22000)...')
    hc22000_path = os.path.join(HCOV_DIR, strip_capture_extension(handshake_path) + '.hc22000')
    log_debug(f'hashcat_crack_handshake: hc22000 output path: {hc22000_path}')
    if not convert_cap_to_hc22000(handshake_path, hc22000_path, packets):
        colored_log('error', 'Failed to convert .cap to hc22000 format.')
        log_debug('hashcat_crack_handshake: convert_cap_to_hc22000 returned False')
        return None
    if not warmup_hashcat_kernel(hc22000_path):
        log_debug('hashcat_crack_handshake: warmup failed, continuing anyway')
    log_debug('hashcat_crack_handshake: conversion OK, calling crack_with_hashcat')
    result = crack_with_hashcat(hc22000_path, wordlist_path, display_essid, gpu_is_discrete)
    log_debug(f'hashcat_crack_handshake: crack_with_hashcat returned {result!r}')
    try:
        os.remove(hc22000_path)
        log_debug(f'hashcat_crack_handshake: cleaned up temp file {hc22000_path}')
    except OSError:
        pass
    return result

class HashcatBackend:
    def __init__(self, gpu_is_discrete: bool = False, packets_map: dict | None = None):
        self.gpu_is_discrete = gpu_is_discrete
        self.packets_map = packets_map or {}

    def crack(self, handshake_path: str, wordlist_path: str, display_essid: str) -> str | None:
        packets = self.packets_map.get(handshake_path)
        return hashcat_crack_handshake(
            handshake_path,
            wordlist_path,
            display_essid,
            self.gpu_is_discrete,
            packets
        )
