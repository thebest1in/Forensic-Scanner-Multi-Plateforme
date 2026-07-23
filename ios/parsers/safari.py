"""Safari browser history parser for iOS backups.

Extracts browsing history, downloads, and bookmarks from Safari databases.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from core import logger
from ios.backup import read_manifest_database, resolve_backup_file, open_sqlite_read_only


def parse_safari_history(backup_dir: Path) -> dict[str, Any]:
    """Parse Safari browsing history from History.db."""
    records = read_manifest_database(backup_dir)

    history_record = None
    for record in records:
        rp = record.get("relative_path", "")
        domain = record.get("domain", "")
        if rp.endswith("History.db") and "Safari" in domain:
            history_record = record
            break

    if not history_record:
        logger.info("Safari History.db not found in backup")
        return {"visits": [], "total": 0}

    db_path = resolve_backup_file(backup_dir, history_record["file_id"])
    if not db_path.exists():
        return {"visits": [], "total": 0}

    try:
        conn = open_sqlite_read_only(db_path)
        try:
            rows = conn.execute(
                """
                SELECT
                    v.ROWID,
                    h.url,
                    h.title,
                    v.visit_time,
                    v.load_successful,
                    v.redirect_source,
                    v.history_visits
                FROM history_visits v
                JOIN history_items h ON v.history_item = h.ROWID
                ORDER BY v.visit_time DESC
                LIMIT 5000
                """
            ).fetchall()
        except Exception:
            rows = []
        finally:
            conn.close()

        visits = []
        for row in rows:
            timestamp = _convert_apple_epoch(row[3])
            visits.append({
                "row_id": row[0],
                "url": row[1] or "",
                "title": row[2] or "",
                "date": timestamp,
                "successful": bool(row[4]),
                "redirect_source": row[5] or "",
            })

        logger.info(f"Parsed {len(visits)} Safari visits")
        return {"visits": visits, "total": len(visits)}
    except Exception as e:
        logger.warning(f"Failed to parse Safari history: {e}")
        return {"visits": [], "total": 0, "error": str(e)}


def parse_safari_downloads(backup_dir: Path) -> dict[str, Any]:
    """Parse Safari downloads from the backup."""
    records = read_manifest_database(backup_dir)

    download_record = None
    for record in records:
        rp = record.get("relative_path", "")
        domain = record.get("domain", "")
        if "Downloads" in rp and "Safari" in domain:
            download_record = record
            break

    if not download_record:
        return {"downloads": [], "total": 0}

    db_path = resolve_backup_file(backup_dir, download_record["file_id"])
    if not db_path.exists():
        return {"downloads": [], "total": 0}

    try:
        conn = open_sqlite_read_only(db_path)
        try:
            rows = conn.execute(
                "SELECT ROWID, * FROM downloads ORDER BY date_added DESC LIMIT 1000"
            ).fetchall()
            cols = [d[0] for d in conn.execute("PRAGMA table_info(downloads)").fetchall()]
            downloads = []
            for row in rows:
                downloads.append(dict(zip([c[1] for c in conn.execute("PRAGMA table_info(downloads)").fetchall()], row)))
            return {"downloads": downloads, "total": len(downloads)}
        except Exception:
            return {"downloads": [], "total": 0}
        finally:
            conn.close()
    except Exception as e:
        logger.warning(f"Failed to parse Safari downloads: {e}")
        return {"downloads": [], "total": 0, "error": str(e)}


def parse_safari_bookmarks(backup_dir: Path) -> dict[str, Any]:
    """Parse Safari bookmarks from Bookmarks.db."""
    records = read_manifest_database(backup_dir)

    bookmark_record = None
    for record in records:
        rp = record.get("relative_path", "")
        domain = record.get("domain", "")
        if rp.endswith("Bookmarks.db") and "Safari" in domain:
            bookmark_record = record
            break

    if not bookmark_record:
        return {"bookmarks": [], "total": 0}

    db_path = resolve_backup_file(backup_dir, bookmark_record["file_id"])
    if not db_path.exists():
        return {"bookmarks": [], "total": 0}

    try:
        conn = open_sqlite_read_only(db_path)
        try:
            rows = conn.execute(
                """
                SELECT ROWID, title, url_string, date_added, date_modified
                FROM bookmarks
                WHERE url_string IS NOT NULL
                ORDER BY date_added DESC
                LIMIT 2000
                """
            ).fetchall()
            bookmarks = [
                {"row_id": r[0], "title": r[1] or "", "url": r[2] or "",
                 "added": _convert_apple_epoch(r[3]), "modified": _convert_apple_epoch(r[4])}
                for r in rows
            ]
            return {"bookmarks": bookmarks, "total": len(bookmarks)}
        except Exception:
            return {"bookmarks": [], "total": 0}
        finally:
            conn.close()
    except Exception as e:
        return {"bookmarks": [], "total": 0, "error": str(e)}


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
