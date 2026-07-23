"""Device information parser for iOS backup data.

Extracts and formats device metadata from Info.plist and live queries.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from core import logger
from ios.backup import parse_info_plist, parse_status_plist


# Fields to redact in reports (PII)
_REDACTED_FIELDS = {"SerialNumber", "InternationalMobileEquipmentIdentity",
                     "MobileEquipmentIdentifier", "UniqueDeviceID"}


def extract_device_summary(backup_dir: Path) -> dict[str, Any]:
    """Extract device summary from Info.plist in the backup."""
    info = parse_info_plist(backup_dir)
    if not info:
        return {"error": "Info.plist not found or unreadable"}

    summary = {
        "product_type": info.get("ProductType", "Unknown"),
        "product_version": info.get("ProductVersion", "Unknown"),
        "build_version": info.get("BuildVersion", "Unknown"),
        "device_name": info.get("DeviceName", "Unknown"),
        "model_number": info.get("ModelNumber", "Unknown"),
        "serial_number_redacted": _redact(info.get("SerialNumber", "")),
        "udid": info.get("UniqueDeviceID", ""),
        "backup_date": info.get("LastBackupDate", ""),
        "is_encrypted": info.get("IsEncrypted", False),
        "encryption_key_strength": info.get("EncryptionKeyStrength", 0),
    }
    return summary


def extract_device_info_from_live(stdout: str) -> dict[str, str]:
    """Parse ideviceinfo output into a structured dict."""
    info = {}
    for line in stdout.splitlines():
        if ": " in line:
            key, _, value = line.partition(": ")
            info[key.strip()] = value.strip()
    return info


def redact_device_id(device_id: str) -> str:
    """Redact a device identifier for safe display."""
    return _redact(device_id)


def _redact(value: str) -> str:
    """Redact a sensitive value, showing only last 4 characters."""
    if not value or len(value) <= 4:
        return "****"
    return "*" * (len(value) - 4) + value[-4:]


def build_device_report(backup_dir: Path) -> dict[str, Any]:
    """Build a comprehensive device report from backup data."""
    info = parse_info_plist(backup_dir)
    status = parse_status_plist(backup_dir)

    return {
        "platform": "IOS",
        "device": extract_device_summary(backup_dir),
        "backup_status": {
            "backup_state": status.get("BackupState", "Unknown"),
            "is_full_backup": status.get("IsFullBackup", True),
            "date": status.get("Date", ""),
        },
        "acquisition": {
            "method": "LOCAL_BACKUP",
            "encrypted": info.get("IsEncrypted", False),
            "paired": True,
            "device_locked_during_acquisition": False,
        },
        "limitations": [
            "No physical filesystem acquisition",
            "Non-jailbroken device",
            "Results limited to data present in the local backup",
        ],
    }
