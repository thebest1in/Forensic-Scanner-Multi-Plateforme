"""Call history parser for iOS backups.

Extracts call records from call_history.db in iOS backups.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from core import logger
from ios.backup import read_manifest_database, resolve_backup_file, open_sqlite_read_only


def parse_call_history(backup_dir: Path) -> dict[str, Any]:
    """Parse call history database from the backup."""
    records = read_manifest_database(backup_dir)

    # Find call_history.db
    call_record = None
    for record in records:
        rp = record.get("relative_path", "")
        domain = record.get("domain", "")
        if "call_history" in rp.lower() and "HomeDomain" in domain:
            call_record = record
            break

    if not call_record:
        logger.info("call_history.db not found in backup")
        return {"calls": [], "total": 0}

    db_path = resolve_backup_file(backup_dir, call_record["file_id"])
    if not db_path.exists():
        return {"calls": [], "total": 0}

    try:
        conn = open_sqlite_read_only(db_path)
        try:
            rows = conn.execute(
                """
                SELECT
                    z ROWID,
                    originator_id,
                    address,
                    date,
                    duration,
                    flags,
                    name,
                    country_code,
                    read
                FROM ZCALLRECORD
                ORDER BY date DESC
                LIMIT 5000
                """
            ).fetchall()
        except Exception:
            # Try alternative schema
            try:
                rows = conn.execute(
                    """
                    SELECT
                        ROWID,
                        '',
                        number,
                        date,
                        duration,
                        flags,
                        name,
                        '',
                        0
                    FROM call
                    ORDER BY date DESC
                    LIMIT 5000
                    """
                ).fetchall()
            except Exception:
                rows = []
        finally:
            conn.close()

        calls = []
        for row in rows:
            timestamp = _convert_apple_epoch(row[3])
            direction = "outgoing" if row[5] & 1 else "incoming"
            calls.append({
                "row_id": row[0],
                "number": row[2] or "",
                "date": timestamp,
                "duration_seconds": row[4] or 0,
                "direction": direction,
                "name": row[6] or "",
                "country_code": row[7] or "",
            })

        logger.info(f"Parsed {len(calls)} call records")
        return {"calls": calls, "total": len(calls)}
    except Exception as e:
        logger.warning(f"Failed to parse call history: {e}")
        return {"calls": [], "total": 0, "error": str(e)}


def _convert_apple_epoch(timestamp: int | float | None) -> str:
    """Convert Apple epoch timestamp to ISO format."""
    if not timestamp:
        return ""
    try:
        from datetime import datetime, timezone
        apple_epoch = datetime(2001, 1, 1, tzinfo=timezone.utc)
        dt = apple_epoch.timestamp() + float(timestamp)
        return datetime.fromtimestamp(dt, tz=timezone.utc).isoformat()
    except (ValueError, OSError):
        return str(timestamp)
