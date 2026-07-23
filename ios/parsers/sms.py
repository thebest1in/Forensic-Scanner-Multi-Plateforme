"""SMS/iMessage parser for iOS backups.

Extracts messages from sms.db in iOS backups.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from core import logger
from ios.backup import read_manifest_database, resolve_backup_file, open_sqlite_read_only


def parse_sms(backup_dir: Path) -> dict[str, Any]:
    """Parse SMS/iMessage database from the backup."""
    records = read_manifest_database(backup_dir)

    # Find sms.db in HomeDomain or HomeDomain-Library
    sms_record = None
    for record in records:
        rp = record.get("relative_path", "")
        domain = record.get("domain", "")
        if rp.endswith("sms.db") and "HomeDomain" in domain:
            sms_record = record
            break

    if not sms_record:
        logger.info("sms.db not found in backup")
        return {"messages": [], "total": 0}

    db_path = resolve_backup_file(backup_dir, sms_record["file_id"])
    if not db_path.exists():
        return {"messages": [], "total": 0}

    try:
        conn = open_sqlite_read_only(db_path)
        try:
            rows = conn.execute(
                """
                SELECT
                    m.ROWID,
                    m.text,
                    m.date,
                    m.is_from_me,
                    m.handle_id,
                    m.cache_has_attachments,
                    h.id as phone_number,
                    m.cache_username
                FROM message m
                LEFT JOIN handle h ON m.handle_id = h.ROWID
                ORDER BY m.date DESC
                LIMIT 5000
                """
            ).fetchall()
        finally:
            conn.close()

        messages = []
        for row in rows:
            # iOS stores dates as Apple epoch (seconds since 2001-01-01)
            timestamp = _convert_apple_epoch(row[2])
            messages.append({
                "row_id": row[0],
                "text": row[1] or "",
                "date": timestamp,
                "is_from_me": bool(row[3]),
                "handle_id": row[4],
                "has_attachments": bool(row[5]),
                "phone_number": row[6] or "",
                "direction": "sent" if row[3] else "received",
            })

        logger.info(f"Parsed {len(messages)} SMS/iMessage messages")
        return {"messages": messages, "total": len(messages)}
    except Exception as e:
        logger.warning(f"Failed to parse sms.db: {e}")
        return {"messages": [], "total": 0, "error": str(e)}


def _convert_apple_epoch(timestamp: int | float | None) -> str:
    """Convert Apple epoch timestamp to ISO format."""
    if not timestamp:
        return ""
    try:
        # Apple epoch: 2001-01-01 00:00:00 UTC
        from datetime import datetime, timezone
        apple_epoch = datetime(2001, 1, 1, tzinfo=timezone.utc)
        dt = apple_epoch.timestamp() + float(timestamp)
        return datetime.fromtimestamp(dt, tz=timezone.utc).isoformat()
    except (ValueError, OSError):
        return str(timestamp)
