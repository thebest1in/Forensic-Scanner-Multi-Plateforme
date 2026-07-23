"""Analytics and crash log parser for iOS backups.

Extracts diagnostic data, analytics logs, and crash reports.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from core import logger
from ios.backup import read_manifest_database, resolve_backup_file, open_sqlite_read_only


def parse_analytics(backup_dir: Path) -> dict[str, Any]:
    """Parse analytics databases from the backup."""
    records = read_manifest_database(backup_dir)
    analytics_records = []

    for record in records:
        rp = record.get("relative_path", "")
        domain = record.get("domain", "")
        if "Analytics" in rp or "analytics" in rp:
            analytics_records.append(record)

    results = {"entries": [], "total": 0, "sources": []}

    for record in analytics_records:
        db_path = resolve_backup_file(backup_dir, record["file_id"])
        if not db_path.exists():
            continue

        try:
            conn = open_sqlite_read_only(db_path)
            try:
                tables = [
                    row[0] for row in conn.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    ).fetchall()
                ]
                for table in tables:
                    try:
                        rows = conn.execute(
                            f"SELECT * FROM {table} ORDER BY ROWID DESC LIMIT 200"
                        ).fetchall()
                        cols = [d[1] for d in conn.execute(
                            f"PRAGMA table_info({table})"
                        ).fetchall()]
                        for row in rows:
                            results["entries"].append({
                                "table": table,
                                "source": record.get("relative_path", ""),
                                "data": dict(zip(cols, [str(c) for c in row])),
                            })
                        results["sources"].append(f"{record.get('relative_path', '')}:{table}")
                    except Exception:
                        pass
            finally:
                conn.close()
        except Exception:
            pass

    results["total"] = len(results["entries"])
    logger.info(f"Parsed {results['total']} analytics entries from {len(results['sources'])} sources")
    return results


def parse_crash_reports(backup_dir: Path) -> dict[str, Any]:
    """Parse crash report files from the backup."""
    records = read_manifest_database(backup_dir)
    crash_records = []

    for record in records:
        rp = record.get("relative_path", "")
        if "Crash" in rp or "crash" in rp or rp.endswith(".ips"):
            crash_records.append(record)

    crashes = []
    for record in crash_records:
        file_path = resolve_backup_file(backup_dir, record["file_id"])
        if file_path.exists():
            try:
                content = file_path.read_text(encoding="utf-8", errors="replace")
                crashes.append({
                    "file": record.get("relative_path", ""),
                    "domain": record.get("domain", ""),
                    "size": file_path.stat().st_size,
                    "preview": content[:500],
                })
            except Exception:
                pass

    logger.info(f"Parsed {len(crashes)} crash reports")
    return {"crashes": crashes, "total": len(crashes)}


def parse_data_usage(backup_dir: Path) -> dict[str, Any]:
    """Parse data usage records from the backup."""
    records = read_manifest_database(backup_dir)

    usage_record = None
    for record in records:
        rp = record.get("relative_path", "")
        if "DataUsage" in rp and rp.endswith((".db", ".sqlite")):
            usage_record = record
            break

    if not usage_record:
        return {"apps": [], "total": 0}

    db_path = resolve_backup_file(backup_dir, usage_record["file_id"])
    if not db_path.exists():
        return {"apps": [], "total": 0}

    try:
        conn = open_sqlite_read_only(db_path)
        try:
            tables = [
                row[0] for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            ]
            app_usage = []
            for table in tables:
                if "process" in table.lower() or "app" in table.lower():
                    try:
                        rows = conn.execute(
                            f"SELECT * FROM {table} LIMIT 500"
                        ).fetchall()
                        cols = [d[1] for d in conn.execute(
                            f"PRAGMA table_info({table})"
                        ).fetchall()]
                        for row in rows:
                            app_usage.append(dict(zip(cols, [str(c) for c in row])))
                    except Exception:
                        pass
            return {"apps": app_usage, "total": len(app_usage)}
        finally:
            conn.close()
    except Exception as e:
        return {"apps": [], "total": 0, "error": str(e)}
