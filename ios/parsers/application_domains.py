"""Application domains parser for iOS backups.

Extracts per-application container data, entitlements, and sandbox contents.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from core import logger
from ios.backup import read_manifest_database, get_backup_domains, resolve_backup_file


def parse_application_domains(backup_dir: Path) -> dict[str, Any]:
    """Parse application container domains from the backup.

    Returns a summary of all app domains with their file counts
    and notable files (databases, plists, keychain items).
    """
    records = read_manifest_database(backup_dir)
    if not records:
        return {"domains": [], "total": 0}

    domains = get_backup_domains(records)
    app_domains = []

    for domain_name, domain_records in sorted(domains.items()):
        if not domain_name.startswith("AppDomain"):
            continue

        bundle_id = domain_name.replace("AppDomain-", "").replace("AppDomainGroup-", "")
        db_files = []
        plist_files = []
        keychain_items = []

        for record in domain_records:
            rp = record.get("relative_path", "")
            if rp.endswith((".db", ".sqlite", ".sqlite3")):
                db_files.append(rp)
            elif rp.endswith(".plist"):
                plist_files.append(rp)
            elif "keychain" in rp.lower():
                keychain_items.append(rp)

        app_domains.append({
            "bundle_id": bundle_id,
            "domain": domain_name,
            "total_files": len(domain_records),
            "database_files": db_files,
            "plist_files": plist_files,
            "keychain_items": keychain_items,
        })

    logger.info(f"Parsed {len(app_domains)} application domains")
    return {"domains": app_domains, "total": len(app_domains)}


def extract_app_keychain_data(backup_dir: Path) -> dict[str, Any]:
    """Extract keychain data references from backup records.

    Note: Actual keychain decryption requires the device key.
    This only identifies keychain-related files.
    """
    records = read_manifest_database(backup_dir)
    keychain_files = []

    for record in records:
        rp = record.get("relative_path", "")
        if "keychain" in rp.lower():
            file_path = resolve_backup_file(backup_dir, record["file_id"])
            keychain_files.append({
                "path": rp,
                "domain": record.get("domain", ""),
                "exists": file_path.exists(),
                "size": file_path.stat().st_size if file_path.exists() else 0,
            })

    return {"keychain_files": keychain_files, "total": len(keychain_files)}


def find_suspicious_domains(app_domains: list[dict]) -> list[dict]:
    """Identify suspicious application domains."""
    suspicious = []
    suspicious_patterns = [
        "hidden", "stealth", "spy", "monitor", "track",
        "keylog", "capture", "surveillance",
    ]

    for domain in app_domains:
        bid = domain.get("bundle_id", "").lower()
        if any(p in bid for p in suspicious_patterns):
            suspicious.append({
                "bundle_id": domain["bundle_id"],
                "reason": "Suspicious name pattern",
            })
        # High keychain usage can be a sign of credential harvesting
        if len(domain.get("keychain_items", [])) > 10:
            suspicious.append({
                "bundle_id": domain["bundle_id"],
                "reason": f"High keychain usage ({len(domain['keychain_items'])} items)",
            })

    return suspicious
