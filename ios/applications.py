"""Installed applications parser for iOS backups.

Extracts application metadata from backup records and installed app listings.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from core import logger
from ios.backup import read_manifest_database, get_backup_domains


# Known system app bundles (not suspicious)
_SYSTEM_DOMAINS = {
    "HomeDomain", "Library", "SystemPreferencesDomain",
    "MobileGestalt", "WirelessDomain", "DataUsageDomain",
    "com.apple.Preferences", "com.apple.mobilesafari",
    "com.apple.mobilemail", "com.apple.MobileSMS",
    "com.apple.mobilecal", "com.apple.Passbook",
    "com.apple.Tencent Maps", "com.apple.mobileme.fmip1",
    "com.apple.preferences.location",
}

# Known spyware/stalkerware indicators (partial list)
_KNOWN_SPYWARE_INDICATORS = [
    "com.flexispy", "com.spybubble", "com.highster",
    "com.spystealth", "com.mspy", "com.hoverwatch",
    "com.cerberus", "com.prey", "com.lookout",
    "com.avast.android.mobilesecurity",
    "com.snoopza", "com.childmonitor",
]


def parse_installed_apps(backup_dir: Path) -> dict[str, Any]:
    """Parse installed applications from the backup Manifest.db."""
    records = read_manifest_database(backup_dir)
    if not records:
        return {"apps": [], "total": 0}

    domains = get_backup_domains(records)
    app_domains = {}
    for domain, domain_records in domains.items():
        # App domains typically look like "AppDomain-com.example.app"
        if domain.startswith("AppDomain-"):
            bundle_id = domain[len("AppDomain-"):]
            app_domains[bundle_id] = domain_records

    apps = []
    for bundle_id, files in sorted(app_domains.items()):
        app_info = {
            "bundle_id": bundle_id,
            "file_count": len(files),
            "has_plist": any(
                f["relative_path"].endswith(".plist") for f in files
            ),
            "has_database": any(
                f["relative_path"].endswith((".db", ".sqlite", ".sqlite3"))
                for f in files
            ),
            "suspicious": _is_suspicious_app(bundle_id),
        }
        # Extract app container size
        total_size = 0
        for f in files:
            resolved = backup_dir / f["file_id"][:2] / f["file_id"]
            if resolved.exists():
                total_size += resolved.stat().st_size
        app_info["total_size_bytes"] = total_size
        apps.append(app_info)

    suspicious = [a for a in apps if a["suspicious"]]
    if suspicious:
        logger.warning(
            f"Found {len(suspicious)} suspicious app(s): "
            + ", ".join(a["bundle_id"] for a in suspicious[:5])
        )

    return {
        "apps": apps,
        "total": len(apps),
        "suspicious_count": len(suspicious),
        "suspicious_apps": [a["bundle_id"] for a in suspicious],
    }


def _is_suspicious_app(bundle_id: str) -> bool:
    """Check if a bundle ID matches known spyware patterns."""
    bid_lower = bundle_id.lower()
    # Check against known spyware
    for indicator in _KNOWN_SPYWARE_INDICATORS:
        if indicator in bid_lower:
            return True
    # Heuristic: apps with "hidden", "stealth", "spy", "monitor" in name
    suspicious_keywords = ["hidden", "stealth", "spy", "monitor", "track",
                           "surveillance", "keylog", "capture"]
    return any(kw in bid_lower for kw in suspicious_keywords)


def extract_app_permissions(apps: list[dict]) -> dict[str, Any]:
    """Analyze app permissions from entitlements (if available in backup)."""
    # This is a placeholder — full entitlement extraction requires
    # parsing embedded.mobileprovision or entitlements.plist per app
    return {
        "total_apps_analyzed": len(apps),
        "suspicious_count": sum(1 for a in apps if a.get("suspicious")),
    }
