import os
import sys
import subprocess
import shutil

def is_git_installed() -> bool:
    return shutil.which('git') is not None

def is_git_repo(path: str) -> bool:
    return os.path.isdir(os.path.join(path, '.git'))

def get_current_commit(cwd: str) -> str:
    try:
        result = subprocess.run(
            ['git', 'rev-parse', 'HEAD'],
            capture_output=True, text=True, cwd=cwd, check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        return ""

def get_remote_commit(cwd: str) -> str:
    try:
        result = subprocess.run(
            ['git', 'rev-parse', 'origin/main'],
            capture_output=True, text=True, cwd=cwd, check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        return ""

def get_commits_behind(cwd: str) -> int:
    try:
        result = subprocess.run(
            ['git', 'rev-list', 'HEAD..origin/main', '--count'],
            capture_output=True, text=True, cwd=cwd, check=True
        )
        return int(result.stdout.strip())
    except (subprocess.CalledProcessError, ValueError):
        return 0

def fetch_updates(cwd: str) -> bool:
    try:
        # Fetch with a timeout so it doesn't hang if offline
        subprocess.run(
            ['git', 'fetch', 'origin', 'main'],
            capture_output=True, cwd=cwd, timeout=5, check=True
        )
        return True
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
        return False

def check_and_update():
    # Only run in the context of the main script directory
    script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
    if not is_git_installed():
        return
        
    if not is_git_repo(script_dir):
        return

    # Check for updates silently
    print("Checking for updates...")
    if not fetch_updates(script_dir):
        # Offline or fetch failed, just return
        return

    behind_count = get_commits_behind(script_dir)

    if behind_count > 0:
        local_commit = get_current_commit(script_dir)
        remote_commit = get_remote_commit(script_dir)
        
        if not local_commit or not remote_commit:
            return
        print("\n\033[96m" + "="*60 + "\033[0m")
        print("\033[93m[!] Downloading an update from GitHub...\033[0m")
        
        # Get changelog
        try:
            log_out = subprocess.run(
                ['git', 'log', f'{local_commit}..{remote_commit}', '--oneline', '--color=always'],
                capture_output=True, text=True, cwd=script_dir
            )
            if log_out.stdout.strip():
                print("\n\033[92mWhat's new:\033[0m")
                for line in log_out.stdout.strip().split('\n'):
                    print(f"  {line}")
        except Exception:
            pass
            
        print("\033[96m" + "="*60 + "\033[0m\n")
        print("Applying update...")
        try:
            subprocess.run(
                ['git', 'pull', 'origin', 'main'],
                cwd=script_dir, check=True
            )
            print("\033[92mUpdate successful! Restarting program...\033[0m\n")
            
            # Restart the program
            os.execv(sys.executable, [sys.executable] + sys.argv)
            
        except subprocess.CalledProcessError:
            print("\033[91mFailed to apply update. You may have local conflicts or network issues.\033[0m")
            print("Continuing with the current version...\n")
