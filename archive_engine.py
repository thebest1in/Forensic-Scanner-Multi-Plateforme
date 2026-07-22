import os
import re
import json
import zipfile
import tarfile
import sqlite3
import shutil
from pathlib import Path

from core import logger


# ============================================================
# ZERO-CLICK DOMAIN IOCs (Citizen Lab + Amnesty Tech)
# ============================================================

ZER0CLICK_DOMAINS = {
    "pegasus": [
        "nso.com", "citizenlab.ca", "wotogule.com", "sentrycloaking.com",
        "invis1bleshield.com", "flexispy.com", "highstermobile.com",
        "mspy.com", "spyera.com", "thespybubble.com",
    ],
    "novispy": [
        "cits.rnks.gov.rs",
    ],
    "finspy": [
        "finfisher.com", "finfisher.org",
    ],
    "hackingteam": [
        "hackingteam.com", "hackingteam.it",
    ],
}

# Known malicious package names
MALICIOUS_PACKAGES = {
    "com.flexispy", "com.mspy.lite", "com.mspy.pro", "com.cerberus",
    "com.spybubble", "com.mobilespy", "com.android.sys.update.co",
    "com.android.service.update", "com.google.service.helper",
    "com.xiaomi.system.update.service", "com.droidjack",
    "net.droidjack.server", "com.sandrorat",
}


class ArchiveEngine:
    """Offline forensic engine for bugreport ZIPs and backup tarballs."""

    def __init__(self, archive_path: str | Path, case_id: str = ""):
        self._archive = Path(archive_path)
        self._case_id = case_id or f"case_{int(__import__('time').time())}"
        self._extract_dir: Path | None = None
        self._results: dict[str, Path] = {}
        self._sqlite_hits: list[dict] = []
        self._domain_hits: list[dict] = []
        self._artifact_map: list[dict] = []

    @property
    def extract_dir(self) -> Path | None:
        return self._extract_dir

    @property
    def results(self) -> dict[str, Path]:
        return self._results.copy()

    @property
    def sqlite_hits(self) -> list[dict]:
        return self._sqlite_hits.copy()

    @property
    def domain_hits(self) -> list[dict]:
        return self._domain_hits.copy()

    @property
    def artifact_map(self) -> list[dict]:
        return self._artifact_map.copy()

    def ingest(self, on_progress=None) -> dict[str, Path]:
        """Main entry: detect archive type, extract, parse SQLite, scan domains."""
        if not self._archive.exists():
            raise FileNotFoundError(f"Archive not found: {self._archive}")

        self._extract_dir = Path(__file__).parent / f"offline_{self._case_id}"
        self._extract_dir.mkdir(exist_ok=True)

        _report(on_progress, 0, f"Detecting archive type: {self._archive.name}...")

        if self._archive.suffix.lower() == ".zip" or zipfile.is_zipfile(self._archive):
            self._extract_zip(on_progress)
        elif self._archive.suffix.lower() in (".tar", ".tar.gz", ".tgz", ".tar.bz2"):
            self._extract_tar(on_progress)
        else:
            raise ValueError(f"Unsupported archive format: {self._archive.suffix}")

        _report(on_progress, 50, "Scanning extracted files...")

        # Index all extracted files
        self._index_files()

        _report(on_progress, 65, "Parsing SQLite databases...")
        self._parse_sqlite_databases()

        _report(on_progress, 80, "Hunting zero-click domains...")
        self._hunt_zero_click_domains()

        _report(on_progress, 90, "Building artifact map...")
        self._build_artifact_map()

        _report(on_progress, 95, "Ingestion complete.")
        logger.success(
            f"Archive ingested: {len(self._results)} files, "
            f"{len(self._sqlite_hits)} DB hits, {len(self._domain_hits)} domain hits"
        )
        return self._results

    def _extract_zip(self, on_progress=None):
        """Extract ZIP archive (bugreport or backup)."""
        _report(on_progress, 5, "Extracting ZIP archive...")
        try:
            with zipfile.ZipFile(self._archive, "r") as zf:
                total = len(zf.namelist())
                for i, name in enumerate(zf.namelist()):
                    if i % 50 == 0:
                        progress = 5 + (i / total) * 35
                        _report(on_progress, progress, f"Extracting: {name[:60]}...")
                    zf.extract(name, self._extract_dir)
            logger.success(f"ZIP extracted: {total} files")
        except zipfile.BadZipFile as e:
            logger.error(f"Corrupt ZIP: {e}")
            raise

    def _extract_tar(self, on_progress=None):
        """Extract TAR archive."""
        _report(on_progress, 5, "Extracting TAR archive...")
        try:
            with tarfile.open(self._archive) as tf:
                members = tf.getmembers()
                total = len(members)
                for i, member in enumerate(members):
                    if i % 50 == 0:
                        progress = 5 + (i / total) * 35
                        _report(on_progress, progress, f"Extracting: {member.name[:60]}...")
                    tf.extract(member, self._extract_dir)
            logger.success(f"TAR extracted: {total} files")
        except Exception as e:
            logger.error(f"TAR extraction failed: {e}")
            raise

    def _index_files(self):
        """Index all extracted files by type."""
        for file_path in self._extract_dir.rglob("*"):
            if not file_path.is_file():
                continue
            ext = file_path.suffix.lower()
            if ext in (".txt", ".log"):
                self._results[file_path.stem] = file_path
            elif ext == ".db" or ext == ".sqlite" or ext == ".sqlite3":
                self._results[f"db_{file_path.stem}"] = file_path

    def _parse_sqlite_databases(self):
        """Open and scan all SQLite databases for suspicious data."""
        db_files = [p for p in self._extract_dir.rglob("*")
                    if p.is_file() and p.suffix.lower() in (".db", ".sqlite", ".sqlite3")]

        for db_path in db_files:
            try:
                self._scan_sqlite_db(db_path)
            except Exception as e:
                logger.warning(f"Cannot read SQLite: {db_path.name}: {e}")

    def _scan_sqlite_db(self, db_path: Path):
        """Scan a single SQLite database for suspicious entries."""
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            cursor = conn.cursor()

            # Get table names
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]

            for table in tables:
                try:
                    cursor.execute(f"PRAGMA table_info(`{table}`)")
                    columns = [col[1] for row in cursor.fetchall() for col in [row]]
                    columns = [row[1] for row in cursor.execute(f"PRAGMA table_info(`{table}`)")]

                    # Check for URL/message columns that might contain zero-click links
                    url_cols = [c for c in columns if any(
                        kw in c.lower() for kw in ("url", "link", "message", "body", "text", "content")
                    )]

                    for col in url_cols:
                        try:
                            cursor.execute(f"SELECT DISTINCT `{col}` FROM `{table}` WHERE `{col}` IS NOT NULL LIMIT 500")
                            for row in cursor.fetchall():
                                if row[0] and isinstance(row[0], str):
                                    self._check_content_for_iocs(row[0], db_path.name, table, col)
                        except Exception:
                            continue

                except Exception:
                    continue

            conn.close()

        except sqlite3.Error:
            pass

    def _check_content_for_iocs(self, content: str, source_db: str, table: str, column: str):
        """Check text content for zero-click domains and malicious packages."""
        content_lower = content.lower()

        # Check for zero-click domains
        for category, domains in ZER0CLICK_DOMAINS.items():
            for domain in domains:
                if domain.lower() in content_lower:
                    self._domain_hits.append({
                        "domain": domain,
                        "category": category,
                        "source": f"{source_db}:{table}.{column}",
                        "snippet": content[:200],
                    })
                    logger.warning(f"Zero-click domain found: {domain} in {source_db}:{table}")

        # Check for malicious package names
        for pkg in MALICIOUS_PACKAGES:
            if pkg in content_lower:
                self._domain_hits.append({
                    "domain": pkg,
                    "category": "malicious_package",
                    "source": f"{source_db}:{table}.{column}",
                    "snippet": content[:200],
                })
                logger.warning(f"Malicious package found: {pkg} in {source_db}:{table}")

    def _hunt_zero_click_domains(self):
        """Scan all text files for zero-click domain indicators."""
        text_files = [p for p in self._extract_dir.rglob("*")
                      if p.is_file() and p.suffix.lower() in (".txt", ".log", ".xml", ".json", ".conf")]

        for file_path in text_files:
            try:
                content = file_path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue

            for category, domains in ZER0CLICK_DOMAINS.items():
                for domain in domains:
                    if domain.lower() in content.lower():
                        self._domain_hits.append({
                            "domain": domain,
                            "category": category,
                            "source": file_path.name,
                            "snippet": self._extract_context(content, domain),
                        })
                        logger.warning(f"Zero-click domain: {domain} in {file_path.name}")

    def _build_artifact_map(self):
        """Generate structured file index with initial scan status for UI dropdown."""
        if not self._extract_dir:
            return

        flagged_domains = {h["domain"].lower() for h in self._domain_hits}
        flagged_sources = {h.get("source", "").split(":")[0] for h in self._domain_hits}

        self._artifact_map = []
        for file_path in sorted(self._extract_dir.rglob("*")):
            if not file_path.is_file():
                continue

            size = file_path.stat().st_size
            rel = str(file_path.relative_to(self._extract_dir))

            # Determine initial status
            status = "CLEAN"
            if file_path.name in flagged_sources:
                status = "SUSPICIOUS"

            try:
                content = file_path.read_text(encoding="utf-8", errors="replace")
                content_lower = content.lower()
                for fd in flagged_domains:
                    if fd in content_lower:
                        status = "SUSPICIOUS"
                        break
                if any(mp in content_lower for mp in MALICIOUS_PACKAGES):
                    status = "CRITICAL"
            except Exception:
                content = ""

            self._artifact_map.append({
                "name": file_path.name,
                "path": str(file_path),
                "relative_path": rel,
                "size_bytes": size,
                "size_human": _human_size(size),
                "status": status,
                "extension": file_path.suffix.lower(),
                "has_content": bool(content),
            })

        logger.info(f"Artifact map: {len(self._artifact_map)} files indexed")

    def _extract_context(self, content: str, marker: str, context_chars: int = 100) -> str:
        """Extract surrounding context around a matched marker."""
        idx = content.lower().find(marker.lower())
        if idx == -1:
            return ""
        start = max(0, idx - context_chars)
        end = min(len(content), idx + len(marker) + context_chars)
        return content[start:end].strip()


def ingest_archive(
    archive_path: str | Path,
    case_id: str = "",
    on_progress=None,
) -> dict:
    """Convenience function: ingest an archive and return results dict."""
    engine = ArchiveEngine(archive_path, case_id)
    results = engine.ingest(on_progress)
    return {
        "extract_dir": engine.extract_dir,
        "results": results,
        "sqlite_hits": engine.sqlite_hits,
        "domain_hits": engine.domain_hits,
        "artifact_map": engine.artifact_map,
    }


def _report(on_progress, percent, message):
    if on_progress:
        try:
            on_progress(percent, message)
        except Exception:
            pass


def _human_size(size_bytes: int) -> str:
    """Convert bytes to human-readable size."""
    for unit in ("B", "KB", "MB", "GB"):
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"
