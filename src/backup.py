import os
import shutil
import zipfile
import datetime
from pathlib import Path
from src.console import log_debug, colored_log

# Use the user's Documents folder for a safe backup outside the git repository
BACKUP_DIR = os.path.join(Path.home(), "Documents", "HandshakeCrackerBackups")

def create_safe_backup(handshakes_dir: str):
    """Creates a zip backup of the handshakes directory safely outside the project root."""
    try:
        if not os.path.exists(handshakes_dir):
            return
            
        # Check if there are actual files to backup to prevent backing up empty folders
        has_files = False
        for root, _, files in os.walk(handshakes_dir):
            if files:
                has_files = True
                break
                
        if not has_files:
            return

        os.makedirs(BACKUP_DIR, exist_ok=True)
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_filename = f"handshakes_backup_{timestamp}.zip"
        backup_path = os.path.join(BACKUP_DIR, backup_filename)

        with zipfile.ZipFile(backup_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, _, files in os.walk(handshakes_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, handshakes_dir)
                    zipf.write(file_path, arcname)
                    
        log_debug(f"Backup created successfully at: {backup_path}")
        
        # Keep only the last 5 backups to save space
        backups = sorted([os.path.join(BACKUP_DIR, f) for f in os.listdir(BACKUP_DIR) if f.endswith(".zip")])
        while len(backups) > 5:
            oldest = backups.pop(0)
            os.remove(oldest)
            
    except Exception as e:
        log_debug(f"Failed to create backup: {e}")

def restore_from_backup(handshakes_dir: str) -> bool:
    """Restores the latest backup if the handshakes directory is empty."""
    try:
        if not os.path.exists(BACKUP_DIR):
            return False
            
        backups = sorted([os.path.join(BACKUP_DIR, f) for f in os.listdir(BACKUP_DIR) if f.endswith(".zip")])
        if not backups:
            return False
            
        latest_backup = backups[-1]
        
        # Only restore if current directory is empty
        has_files = False
        if os.path.exists(handshakes_dir):
            for root, _, files in os.walk(handshakes_dir):
                if files:
                    has_files = True
                    break
                    
        if has_files:
            return False # Don't overwrite existing files
            
        os.makedirs(handshakes_dir, exist_ok=True)
        with zipfile.ZipFile(latest_backup, 'r') as zipf:
            zipf.extractall(handshakes_dir)
            
        colored_log("success", f"Auto-restored handshakes from safe backup: {os.path.basename(latest_backup)}")
        return True
    except Exception as e:
        log_debug(f"Failed to restore backup: {e}")
        return False
