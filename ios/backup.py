"""iOS backup structure parser.

Parses Manifest.db, Info.plist, Status.plist, and resolves backup file paths.
"""
from __future__ import annotations

import plistlib
import sqlite3
from pathlib import Path
from typing import Any

from core import logger


def read_plist(path: Path) -> dict[str, Any]:
    """Read a binary or XML plist file and return its contents as a dict."""
    if not path.exists():
        return {}
    try:
        with path.open("rb") as f:
            value = plistlib.load(f)
        return value if isinstance(value, dict) else {"value": value}
    except Exception as e:
        logger.warning(f"Failed to parse plist {path.name}: {e}")
        return {}


def open_sqlite_read_only(path: Path) -> sqlite3.Connection:
    """Open a SQLite database in read-only mode."""
    uri = f"file:{path.as_posix()}?mode=ro"
    return sqlite3.connect(uri, uri=True)


def read_manifest_database(backup_dir: Path) -> list[dict[str, Any]]:
    """Parse Manifest.db to enumerate all backup records.

    Returns list of {file_id, domain, relative_path, flags, metadata} dicts.
    """
    db_path = backup_dir / "Manifest.db"
    if not db_path.exists():
        # Unencrypted backups may use Manifest.mbdb
        mbdb_path = backup_dir / "Manifest.mbdb"
        if mbdb_path.exists():
            return _read_mbdb(mdb_path)
        logger.warning("Manifest.db not found in backup directory")
        return []

    try:
        connection = open_sqlite_read_only(db_path)
        try:
            rows = connection.execute(
                """
                SELECT fileID, domain, relativePath, flags, file
                FROM Files
                """
            ).fetchall()
        finally:
            connection.close()

        records = []
        for row in rows:
            records.append({
                "file_id": row[0],
                "domain": row[1],
                "relative_path": row[2],
                "flags": row[3],
                "metadata": row[4],
            })
        logger.info(f"Parsed Manifest.db: {len(records)} backup records")
        return records
    except Exception as e:
        logger.error(f"Failed to read Manifest.db: {e}")
        return []


def _read_mbdb(mbdb_path: Path) -> list[dict[str, Any]]:
    """Fallback parser for Manifest.mbdb (older iOS backup format)."""
    logger.info("Parsing Manifest.mbdb (legacy format)")
    try:
        data = mbdb_path.read_bytes()
        records = []
        offset = 0
        # MBDB header: "mbdb" + version (4 bytes)
        if data[:4] != b"mbdb":
            return []
        offset = 8  # skip header

        while offset < len(data) - 4:
            try:
                # Each record has: domain, filename, link_target, data_hash, ...
                domain = _read_mbdb_string(data, offset)
                offset = _skip_mbdb_string(data, offset)
                filename = _read_mbdb_string(data, offset)
                offset = _skip_mbdb_string(data, offset)
                link_target = _read_mbdb_string(data, offset)
                offset = _skip_mbdb_string(data, offset)
                data_hash = _read_mbdb_string(data, offset)
                offset = _skip_mbdb_string(data, offset)

                # Skip remaining fields (8 x uint32 + properties)
                for _ in range(8):
                    offset += 4
                prop_len = int.from_bytes(data[offset:offset + 2], "big")
                offset += 2 + prop_len

                records.append({
                    "file_id": data_hash.hex() if data_hash else "",
                    "domain": domain,
                    "relative_path": filename,
                    "flags": 0,
                    "metadata": None,
                })
            except (IndexError, ValueError):
                break
        logger.info(f"Parsed Manifest.mbdb: {len(records)} records")
        return records
    except Exception as e:
        logger.warning(f"Failed to parse Manifest.mbdb: {e}")
        return []


def _read_mbdb_string(data: bytes, offset: int) -> bytes:
    if offset + 2 > len(data):
        return b""
    length = int.from_bytes(data[offset:offset + 2], "big")
    return data[offset + 2:offset + 2 + length]


def _skip_mbdb_string(data: bytes, offset: int) -> int:
    if offset + 2 > len(data):
        return len(data)
    length = int.from_bytes(data[offset:offset + 2], "big")
    return offset + 2 + length


def resolve_backup_file(backup_dir: Path, file_id: str) -> Path:
    """Resolve a backup file path using the hashed layout.

    Backup files are stored as: backup_dir/XX/file_id
    where XX are the first two characters of the file_id.
    """
    if not file_id or len(file_id) < 2:
        return backup_dir / "unknown"
    return backup_dir / file_id[:2] / file_id


def parse_info_plist(backup_dir: Path) -> dict[str, Any]:
    """Parse Info.plist from the backup directory."""
    info_path = backup_dir / "Info.plist"
    return read_plist(info_path)


def parse_status_plist(backup_dir: Path) -> dict[str, Any]:
    """Parse Status.plist from the backup directory."""
    status_path = backup_dir / "Status.plist"
    return read_plist(status_path)


def get_backup_domains(records: list[dict[str, Any]]) -> dict[str, list[dict]]:
    """Group backup records by domain (app bundle ID)."""
    domains: dict[str, list[dict]] = {}
    for record in records:
        domain = record.get("domain", "unknown")
        if domain not in domains:
            domains[domain] = []
        domains[domain].append(record)
    return domains


def list_backup_files(
    backup_dir: Path, domains: list[str] | None = None
) -> list[dict[str, Any]]:
    """List all files in the backup, optionally filtered by domain."""
    records = read_manifest_database(backup_dir)
    if domains:
        records = [r for r in records if r["domain"] in domains]

    files = []
    for record in records:
        file_path = resolve_backup_file(backup_dir, record["file_id"])
        files.append({
            **record,
            "resolved_path": str(file_path),
            "exists": file_path.exists(),
            "size": file_path.stat().st_size if file_path.exists() else 0,
        })
    return files


def extract_backup_tree(backup_dir: Path) -> dict[str, Any]:
    """Build a tree structure of the backup contents by domain."""
    records = read_manifest_database(backup_dir)
    domains = get_backup_domains(records)

    tree = {}
    for domain, domain_records in sorted(domains.items()):
        tree[domain] = {
            "file_count": len(domain_records),
            "files": [
                {
                    "path": r["relative_path"],
                    "file_id": r["file_id"],
                    "exists": resolve_backup_file(
                        backup_dir, r["file_id"]
                    ).exists(),
                }
                for r in domain_records
                if r["relative_path"]
            ]
        }
    return tree
