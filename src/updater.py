import os
import sys
import subprocess
import shutil

def is_git_installed() -> bool:
    """Check if git is available in the system PATH."""
    return shutil.which('git') is not None

def is_git_repo(path: str) -> bool:
    """Check if the given path contains a .git directory."""
    return os.path.isdir(os.path.join(path, '.git'))

def get_current_commit(cwd: str) -> str:
    """Get the current local commit hash."""
    try:
        result = subprocess.run(
            ['git', 'rev-parse', 'HEAD'],
            capture_output=True, text=True, cwd=cwd, check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        return ""

def get_remote_commit(cwd: str) -> str:
    """Get the latest remote commit hash for origin/main."""
    try:
        result = subprocess.run(
            ['git', 'rev-parse', 'origin/main'],
            capture_output=True, text=True, cwd=cwd, check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        return ""

def get_commits_behind(cwd: str) -> int:
    """Check how many commits the local branch is behind origin/main."""
    try:
        result = subprocess.run(
            ['git', 'rev-list', 'HEAD..origin/main', '--count'],
            capture_output=True, text=True, cwd=cwd, check=True
        )
        return int(result.stdout.strip())
    except (subprocess.CalledProcessError, ValueError):
        return 0

def fetch_updates(cwd: str) -> bool:
    """Run git fetch with a short timeout to fail fast if offline."""
    try:
        subprocess.run(
            ['git', 'fetch', 'origin', 'main'],
            capture_output=True, cwd=cwd, timeout=5, check=True
        )
        return True
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
        return False

def check_and_update() -> None:
    """
    Check GitHub for updates and apply them automatically if available.
    Runs git fetch with timeout, then git pull if behind.
    Restarts the program after successful update.
    Safe to fail silently — all errors are caught.
    """
    script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
    if not is_git_installed():
        return
        
    if not is_git_repo(script_dir):
        return

    # Check for updates silently
    if not fetch_updates(script_dir):
        return

    behind_count = get_commits_behind(script_dir)

    if behind_count > 0:
        local_commit = get_current_commit(script_dir)
        remote_commit = get_remote_commit(script_dir)
        
        if not local_commit or not remote_commit:
            return
        
        print("\n" + "="*60)
        print("[!] Update found. Downloading...")
        
        # Get changelog
        try:
            log_out = subprocess.run(
                ['git', 'log', f'{local_commit}..{remote_commit}', '--oneline', '--color=never'],
                capture_output=True, text=True, cwd=script_dir
            )
            if log_out.stdout.strip():
                print("\nWhat's new:")
                for line in log_out.stdout.strip().split('\n'):
                    print(f"  {line}")
        except Exception:
            pass
            
        print("="*60 + "\n")
        print("Applying update...")
        try:
            subprocess.run(
                ['git', 'pull', 'origin', 'main'],
                cwd=script_dir, check=True, timeout=30, capture_output=True
            )
            print("Update successful! Restarting program...\n")
            
            # Safely restart program on Windows/Linux
            subprocess.Popen([sys.executable] + sys.argv)
            sys.exit(0)
            
        except subprocess.TimeoutExpired:
            print("Update timed out. Continuing with current version...\n")
        except subprocess.CalledProcessError:
            print("Failed to apply update. You may have local conflicts or network issues.")
            print("Continuing with the current version...\n")
