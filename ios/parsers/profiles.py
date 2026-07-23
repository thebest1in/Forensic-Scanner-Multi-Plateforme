"""Configuration profiles parser for iOS backups.

Extracts MDM profiles, VPN configurations, and certificate data.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from core import logger
from ios.backup import read_manifest_database, resolve_backup_file, read_plist


def parse_configuration_profiles(backup_dir: Path) -> dict[str, Any]:
    """Parse installed configuration profiles from the backup."""
    records = read_manifest_database(backup_dir)

    profiles = []
    for record in records:
        rp = record.get("relative_path", "")
        domain = record.get("domain", "")

        # Configuration profiles are in ConfigurationProfiles domain
        if "Profile" in domain or "configuration" in rp.lower():
            file_path = resolve_backup_file(backup_dir, record["file_id"])
            if file_path.exists():
                try:
                    plist_data = read_plist(file_path)
                    if plist_data:
                        profiles.append({
                            "file": rp,
                            "domain": domain,
                            "payload_type": plist_data.get("PayloadType", ""),
                            "display_name": plist_data.get("PayloadDisplayName", ""),
                            "identifier": plist_data.get("PayloadIdentifier", ""),
                            "organization": plist_data.get("PayloadOrganization", ""),
                            "description": plist_data.get("PayloadDescription", ""),
                        })
                except Exception:
                    pass

    logger.info(f"Parsed {len(profiles)} configuration profiles")
    return {"profiles": profiles, "total": len(profiles)}


def parse_vpn_configurations(backup_dir: Path) -> dict[str, Any]:
    """Parse VPN configurations from the backup."""
    records = read_manifest_database(backup_dir)
    vpn_configs = []

    for record in records:
        rp = record.get("relative_path", "")
        domain = record.get("domain", "")

        if "VPN" in rp or "vpn" in rp.lower():
            file_path = resolve_backup_file(backup_dir, record["file_id"])
            if file_path.exists():
                try:
                    plist_data = read_plist(file_path)
                    if plist_data:
                        vpn_configs.append({
                            "file": rp,
                            "domain": domain,
                            "vpn_type": plist_data.get("VPNType", ""),
                            "remote_identifier": plist_data.get("RemoteIdentifier", ""),
                            "local_identifier": plist_data.get("LocalIdentifier", ""),
                        })
                except Exception:
                    pass

    return {"vpn_configs": vpn_configs, "total": len(vpn_configs)}


def parse_managed_devices(backup_dir: Path) -> dict[str, Any]:
    """Parse MDM managed device profiles."""
    records = read_manifest_database(backup_dir)
    managed = []

    for record in records:
        rp = record.get("relative_path", "")
        domain = record.get("domain", "")

        if "MDM" in domain or "Managed" in domain:
            file_path = resolve_backup_file(backup_dir, record["file_id"])
            if file_path.exists():
                try:
                    plist_data = read_plist(file_path)
                    if plist_data:
                        managed.append({
                            "file": rp,
                            "domain": domain,
                            "payload_type": plist_data.get("PayloadType", ""),
                            "display_name": plist_data.get("PayloadDisplayName", ""),
                        })
                except Exception:
                    pass

    return {"managed_profiles": managed, "total": len(managed)}
