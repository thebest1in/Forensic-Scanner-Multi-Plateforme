"""Contacts parser for iOS backups.

Extracts contacts from AddressBook.sqlitedb or Contacts.sqlite in iOS backups.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from core import logger
from ios.backup import read_manifest_database, resolve_backup_file, open_sqlite_read_only


def parse_contacts(backup_dir: Path) -> dict[str, Any]:
    """Parse contacts database from the backup."""
    records = read_manifest_database(backup_dir)

    # Find contacts database
    contact_record = None
    for record in records:
        rp = record.get("relative_path", "")
        domain = record.get("domain", "")
        if ("AddressBook" in rp or "Contacts" in rp) and rp.endswith((".db", ".sqlite")):
            contact_record = record
            break

    if not contact_record:
        logger.info("Contacts database not found in backup")
        return {"contacts": [], "total": 0}

    db_path = resolve_backup_file(backup_dir, contact_record["file_id"])
    if not db_path.exists():
        return {"contacts": [], "total": 0}

    try:
        conn = open_sqlite_read_only(db_path)
        try:
            # Try ZABCDRECORD schema first (newer iOS)
            try:
                rows = conn.execute(
                    """
                    SELECT
                        z_pk,
                        zFIRSTNAME,
                        zLASTNAME,
                        zORGANIZATION,
                        zEMAILADDRESS,
                        zPHONENUMBER,
                        zCREATIONDATE,
                        zMODIFICATIONDATE
                    FROM ZABCDRECORD
                    LIMIT 10000
                    """
                ).fetchall()
            except Exception:
                # Fallback to older schema
                rows = conn.execute(
                    """
                    SELECT
                        ROWID,
                        First,
                        Last,
                        Organization,
                        value,
                        '',
                        '',
                        ''
                    FROM ABPerson
                    LEFT JOIN ABMultiValue ON ABMultiValue.record_id = ABPerson.ROWID
                    LIMIT 10000
                    """
                ).fetchall()

            contacts = []
            for row in rows:
                contacts.append({
                    "row_id": row[0],
                    "first_name": row[1] or "",
                    "last_name": row[2] or "",
                    "organization": row[3] or "",
                    "email": row[4] or "",
                    "phone": row[5] or "",
                    "created": _convert_apple_epoch(row[6]),
                    "modified": _convert_apple_epoch(row[7]),
                })

            logger.info(f"Parsed {len(contacts)} contacts")
            return {"contacts": contacts, "total": len(contacts)}
        finally:
            conn.close()
    except Exception as e:
        logger.warning(f"Failed to parse contacts: {e}")
        return {"contacts": [], "total": 0, "error": str(e)}


def _convert_apple_epoch(timestamp: int | float | None) -> str:
    if not timestamp:
        return ""
    try:
        from datetime import datetime, timezone
        apple_epoch = datetime(2001, 1, 1, tzinfo=timezone.utc)
        dt = apple_epoch.timestamp() + float(timestamp)
        return datetime.fromtimestamp(dt, tz=timezone.utc).isoformat()
    except (ValueError, OSError):
        return str(timestamp)
