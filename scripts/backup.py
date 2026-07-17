#!/usr/bin/env python3
"""Automated database backup script with 7-day retention."""

import os
import sys
import shutil
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

# Configuration
BACKUP_DIR = Path(__file__).parent.parent / "backups"
DATABASE_PATH = Path(__file__).parent.parent / "ctf_state.db"
RETENTION_DAYS = 7
MAX_BACKUPS = 10

def get_database_path() -> Path:
    """Get the database path from environment or default."""
    env_path = os.environ.get("CTFTOOLKIT_DB_PATH")
    if env_path:
        return Path(env_path)
    return DATABASE_PATH

def create_backup(db_path: Path) -> Path:
    """
    Create a backup of the SQLite database.
    
    Args:
        db_path: Path to the database file
        
    Returns:
        Path to the backup file
    """
    # Ensure backup directory exists
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    
    # Generate backup filename with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_filename = f"ctf_state_{timestamp}.db"
    backup_path = BACKUP_DIR / backup_filename
    
    # Check if database exists
    if not db_path.exists():
        print(f"Warning: Database not found at {db_path}")
        print("Creating empty database backup...")
        # Create an empty backup marker
        backup_path.write_text(f"# Empty database backup - no database found at {db_path}")
        return backup_path
    
    # Copy database file
    try:
        # Close any open connections first (best effort)
        # In production, you might want to use SQLite's backup API
        shutil.copy2(db_path, backup_path)
        print(f"Backup created: {backup_path}")
        return backup_path
    except Exception as e:
        print(f"Error creating backup: {e}")
        sys.exit(1)

def cleanup_old_backups():
    """Remove backups older than retention period."""
    if not BACKUP_DIR.exists():
        return
    
    cutoff_date = datetime.now() - timedelta(days=RETENTION_DAYS)
    removed = 0
    
    # Get all backup files
    backup_files = sorted(BACKUP_DIR.glob("ctf_state_*.db"))
    
    # Remove old backups
    for backup_file in backup_files:
        # Extract timestamp from filename
        try:
            filename = backup_file.stem
            timestamp_str = filename.replace("ctf_state_", "")
            file_date = datetime.strptime(timestamp_str, "%Y%m%d_%H%M%S")
            
            if file_date < cutoff_date:
                backup_file.unlink()
                removed += 1
                print(f"Removed old backup: {backup_file.name}")
        except (ValueError, OSError) as e:
            print(f"Warning: Could not process {backup_file.name}: {e}")
            continue
    
    # Also enforce maximum backup count
    backup_files = sorted(BACKUP_DIR.glob("ctf_state_*.db"))
    if len(backup_files) > MAX_BACKUPS:
        for old_file in backup_files[:len(backup_files) - MAX_BACKUPS]:
            old_file.unlink()
            removed += 1
            print(f"Removed excess backup: {old_file.name}")
    
    print(f"Total backups removed: {removed}")

def list_backups():
    """List all existing backups."""
    if not BACKUP_DIR.exists():
        print("No backups found.")
        return
    
    backup_files = sorted(BACKUP_DIR.glob("ctf_state_*.db"), reverse=True)
    
    if not backup_files:
        print("No backups found.")
        return
    
    print(f"Existing backups in {BACKUP_DIR}:")
    print("-" * 60)
    
    for i, backup_file in enumerate(backup_files[:20], 1):
        size = backup_file.stat().st_size
        size_str = f"{size / 1024:.1f} KB" if size > 1024 else f"{size} bytes"
        print(f"{i:2d}. {backup_file.name} ({size_str})")
    
    if len(backup_files) > 20:
        print(f"... and {len(backup_files) - 20} more")

def restore_backup(backup_name: str):
    """
    Restore a backup.
    
    Args:
        backup_name: Name of the backup file to restore
    """
    backup_path = BACKUP_DIR / backup_name
    
    if not backup_path.exists():
        print(f"Error: Backup not found: {backup_name}")
        sys.exit(1)
    
    db_path = get_database_path()
    
    # Create backup of current database before restore
    if db_path.exists():
        create_backup(db_path)
    
    # Restore
    try:
        shutil.copy2(backup_path, db_path)
        print(f"Database restored from: {backup_name}")
    except Exception as e:
        print(f"Error restoring backup: {e}")
        sys.exit(1)

def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description="CTF Toolkit Database Backup Utility")
    parser.add_argument("action", choices=["backup", "restore", "list", "cleanup"],
                       help="Action to perform")
    parser.add_argument("--file", help="Backup filename for restore operation")
    parser.add_argument("--db-path", help="Path to database file (overrides default)")
    
    args = parser.parse_args()
    
    if args.db_path:
        os.environ["CTFTOOLKIT_DB_PATH"] = args.db_path
    
    db_path = get_database_path()
    
    if args.action == "backup":
        create_backup(db_path)
        cleanup_old_backups()
    elif args.action == "restore":
        if not args.file:
            print("Error: --file required for restore")
            sys.exit(1)
        restore_backup(args.file)
    elif args.action == "list":
        list_backups()
    elif args.action == "cleanup":
        cleanup_old_backups()

if __name__ == "__main__":
    main()
