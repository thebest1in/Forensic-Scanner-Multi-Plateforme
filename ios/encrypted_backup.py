"""Encrypted iOS backup support.

Handles encrypted backup decryption using user-provided passwords.
Password is kept in-memory only and never logged or persisted.
"""
from __future__ import annotations

import subprocess
import sys
from getpass import getpass
from pathlib import Path

from core import logger


def prompt_backup_password() -> str | None:
    """Prompt the user for an encrypted backup password.

    Returns the password string, or None if no password was entered.
    The password is stored only in the caller's local variable.
    """
    try:
        password = getpass("Encrypted backup password (empty for unencrypted): ")
    except (EOFError, KeyboardInterrupt):
        return None
    return password if password else None


def is_backup_encrypted(backup_dir: Path) -> bool:
    """Check if an existing backup is encrypted by examining Manifest.plist."""
    from ios.backup import read_plist

    manifest = read_plist(backup_dir / "Manifest.plist")
    if not manifest:
        return False
    # Encrypted backups have IsEncrypted = true or ManifestKey = <data>
    return manifest.get("IsEncrypted", False) or bool(manifest.get("ManifestKey"))


def verify_backup_password(
    backup_dir: Path,
    password: str,
    idevicebackup2_path: str | None = None,
) -> bool:
    """Verify that a password can decrypt an encrypted backup.

    Uses idevicebackup2 with --password to test decryption.
    """
    if not password:
        return False

    tool = idevicebackup2_path or "idevicebackup2"
    try:
        result = subprocess.run(
            [tool, "backup", "--password", password, "--verify", str(backup_dir)],
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
            creationflags=(
                subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
            ),
        )
        output = (result.stdout or "") + (result.stderr or "")
        # idevicebackup2 returns 0 on successful verification
        if result.returncode == 0:
            logger.info("Backup password verified successfully")
            return True
        if "password" in output.lower() and "incorrect" in output.lower():
            logger.warning("Incorrect backup password")
            return False
    except FileNotFoundError:
        logger.warning(f"{tool} not found for password verification")
    except Exception as e:
        logger.warning(f"Password verification failed: {e}")
    return False


def decrypt_backup(
    backup_dir: Path,
    password: str,
    output_dir: Path | None = None,
) -> bool:
    """Decrypt an encrypted backup to a new directory.

    This re-runs idevicebackup2 --decrypt with the password.
    The password reference is cleared after the call.
    """
    if not password:
        return False

    try:
        # Use idevicebackup2 to restore/decrypt
        target = output_dir or backup_dir.parent / f"{backup_dir.name}_decrypted"
        target.mkdir(parents=True, exist_ok=True)

        result = subprocess.run(
            [
                "idevicebackup2", "restore",
                "--password", password,
                "--full",
                str(target),
            ],
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=600,
            creationflags=(
                subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
            ),
        )
        output = (result.stdout or "") + (result.stderr or "")
        if "complete" in output.lower() or result.returncode == 0:
            logger.success(f"Backup decrypted to {target.name}")
            return True
        logger.warning(f"Decryption may have failed: {output[:200]}")
        return False
    except Exception as e:
        logger.error(f"Decryption failed: {e}")
        return False
    finally:
        # Clear password reference
        password = None


def secure_password_handling(func):
    """Decorator that wraps a function to clear password from local scope."""
    def wrapper(*args, password=None, **kwargs):
        try:
            return func(*args, password=password, **kwargs)
        finally:
            password = None
    return wrapper
