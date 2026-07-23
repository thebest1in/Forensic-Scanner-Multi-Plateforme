"""Wi-Fi networks parser for iOS backups.

Extracts known Wi-Fi networks and their connection history.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from core import logger
from ios.backup import read_plist, read_manifest_database, resolve_backup_file


def parse_wifi_networks(backup_dir: Path) -> dict[str, Any]:
    """Parse Wi-Fi network data from the backup.

    Looks for com.apple.wifi plist files in SystemConfiguration domain.
    """
    records = read_manifest_database(backup_dir)
    networks = []

    for record in records:
        rp = record.get("relative_path", "")
        domain = record.get("domain", "")

        if "com.apple.wifi" in rp.lower() or "wifi" in rp.lower():
            file_path = resolve_backup_file(backup_dir, record["file_id"])
            if file_path.exists():
                try:
                    plist_data = read_plist(file_path)
                    if plist_data:
                        extracted = _extract_wifi_from_plist(plist_data, domain)
                        networks.extend(extracted)
                except Exception:
                    pass

    # Deduplicate by SSID
    seen = set()
    unique_networks = []
    for net in networks:
        ssid = net.get("ssid", "")
        if ssid and ssid not in seen:
            seen.add(ssid)
            unique_networks.append(net)
        elif not ssid:
            unique_networks.append(net)

    logger.info(f"Parsed {len(unique_networks)} known Wi-Fi networks")
    return {"networks": unique_networks, "total": len(unique_networks)}


def _extract_wifi_from_plist(data: dict, domain: str) -> list[dict]:
    """Extract Wi-Fi network entries from a plist structure."""
    networks = []

    # Handle different plist formats
    # Recent iOS: data key contains serialized Wi-Fi preferences
    if isinstance(data, dict):
        # Look for remembered networks
        remembered = data.get("RememberedNetworks", [])
        if isinstance(remembered, list):
            for entry in remembered:
                if isinstance(entry, dict):
                    networks.append({
                        "ssid": entry.get("SSID", ""),
                        "security_type": entry.get("SecurityType", ""),
                        "auto_join": entry.get("AutoJoin", True),
                        "last_connected": entry.get("LastConnected", ""),
                        "domain": domain,
                    })

        # Also check for personal hotspot records
        hotspot = data.get("PersonalHotspot", {})
        if isinstance(hotspot, dict) and hotspot.get("Enabled"):
            networks.append({
                "ssid": hotspot.get("SSID", "Personal Hotspot"),
                "security_type": "WPA2",
                "auto_join": True,
                "domain": domain,
                "is_hotspot": True,
            })

    return networks


def parse_wifi_knowledge(backup_dir: Path) -> dict[str, Any]:
    """Parse Wi-Fi knowledge CTDATABASE for richer connection data."""
    records = read_manifest_database(backup_dir)

    wifi_db_record = None
    for record in records:
        rp = record.get("relative_path", "")
        domain = record.get("domain", "")
        if "WiFi" in rp and rp.endswith((".db", ".sqlite")):
            wifi_db_record = record
            break

    if not wifi_db_record:
        return {"networks": [], "total": 0}

    db_path = resolve_backup_file(backup_dir, wifi_db_record["file_id"])
    if not db_path.exists():
        return {"networks": [], "total": 0}

    try:
        from ios.backup import open_sqlite_read_only
        conn = open_sqlite_read_only(db_path)
        try:
            tables = [
                row[0] for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            ]
            networks = []
            for table in tables:
                try:
                    rows = conn.execute(f"SELECT * FROM {table} LIMIT 500").fetchall()
                    cols = [d[1] for d in conn.execute(f"PRAGMA table_info({table})").fetchall()]
                    for row in rows:
                        networks.append(dict(zip(cols, [str(c) for c in row])))
                except Exception:
                    pass
            return {"networks": networks, "total": len(networks)}
        finally:
            conn.close()
    except Exception as e:
        logger.warning(f"Failed to parse Wi-Fi knowledge: {e}")
        return {"networks": [], "total": 0}
