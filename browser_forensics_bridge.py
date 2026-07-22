import re
import sqlite3
import json
import time
from pathlib import Path
from dataclasses import dataclass, field

from core import logger


# ============================================================
# CHROME / WEBVIEW BROWSER FORENSICS
# ============================================================

# Chrome SQLite databases found on Android
_CHROME_DB_PATHS = {
    "history": "databases/Cookies",
    "cookies": "app_webview/Cookies",
    "login_data": "databases/Login Data",
    "web_data": "databases/Web Data",
    "autofill": "databases/Web Data",
    "top_sites": "databases/Top Sites",
    "favicons": "databases/Favicons",
    "snapshots": "app_webview/Default/Sessions",
}

# Suspicious URL patterns (C2 callbacks, exfil endpoints)
_SUSPICIOUS_URL_PATTERNS = [
    r"https?://.*\.(tk|ml|ga|cf|gq|buzz|top|xyz|club)/",
    r"https?://.*ngrok\.(io|com|app)/",
    r"https?://.*duckdns\.org/",
    r"https?://.*\.serveo\.net/",
    r"https?://.*burpcollaborator\.net/",
    r"https?://.*\.interact\.sh/",
    r"https?://.*oast\.(fun|pro|live)/",
    r"https?://.*canarytokens\.com/",
    r"https?://.*pipedream\.net/",
    r"https?://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/",
]


@dataclass
class BrowserVisit:
    """Single browser history entry."""
    url: str = ""
    title: str = ""
    visit_count: int = 0
    last_visit_time: str = ""
    is_suspicious: bool = False
    suspicious_reason: str = ""

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "title": self.title,
            "visit_count": self.visit_count,
            "last_visit_time": self.last_visit_time,
            "is_suspicious": self.is_suspicious,
            "suspicious_reason": self.suspicious_reason,
        }


@dataclass
class BrowserLogin:
    """Chrome saved login/autofill entry."""
    origin_url: str = ""
    username_value: str = ""
    password_length: int = 0
    date_created: str = ""
    blacklisted: bool = False

    def to_dict(self) -> dict:
        return {
            "origin_url": self.origin_url,
            "username_value": self.username_value,
            "password_length": self.password_length,
            "date_created": self.date_created,
            "blacklisted": self.blacklisted,
        }


@dataclass
class BrowserCookie:
    """Chrome cookie entry."""
    host_key: str = ""
    name: str = ""
    path: str = ""
    expires_utc: str = ""
    is_secure: bool = False
    is_httponly: bool = False
    samesite: str = ""
    is_suspicious: bool = False

    def to_dict(self) -> dict:
        return {
            "host_key": self.host_key,
            "name": self.name,
            "path": self.path,
            "expires_utc": self.expires_utc,
            "is_secure": self.is_secure,
            "is_httponly": self.is_httponly,
            "samesite": self.samesite,
            "is_suspicious": self.is_suspicious,
        }


@dataclass
class BrowserForensicsResult:
    """Complete browser forensics result."""
    package_name: str = ""
    db_path: str = ""
    visits: list[dict] = field(default_factory=list)
    logins: list[dict] = field(default_factory=list)
    cookies: list[dict] = field(default_factory=list)
    suspicious_visits: list[dict] = field(default_factory=list)
    total_visits: int = 0
    total_logins: int = 0
    total_cookies: int = 0
    threat_level: str = "CLEAN"

    def to_dict(self) -> dict:
        return {
            "package_name": self.package_name,
            "db_path": self.db_path,
            "total_visits": self.total_visits,
            "total_logins": self.total_logins,
            "total_cookies": self.total_cookies,
            "suspicious_visits": self.suspicious_visits,
            "visits": self.visits[:50],
            "logins": self.logins[:20],
            "cookies": self.cookies[:50],
            "threat_level": self.threat_level,
        }


class BrowserForensicsBridge:
    """Extract and analyze Chrome/WebView artifacts from Android device dumps.

    Parses Chrome's SQLite databases to extract:
    - Browsing history with suspicious URL detection
    - Saved logins/autofill data
    - Cookies (including third-party tracking cookies)
    - Top sites and favicons

    Detects C2 callback URLs, exfil endpoints, and suspicious TLDs.
    """

    def __init__(self):
        self._suspicious_patterns = [re.compile(p, re.IGNORECASE) for p in _SUSPICIOUS_URL_PATTERNS]

    @staticmethod
    def check_available() -> bool:
        """Check if SQLite3 is available (stdlib, always True)."""
        return True

    def scan_dump(self, dump_dir: Path, package_name: str = "com.android.chrome") -> BrowserForensicsResult:
        """Scan a device dump for Chrome browser artifacts."""
        result = BrowserForensicsResult(package_name=package_name)

        chrome_dirs = self._find_chrome_dirs(dump_dir, package_name)
        if not chrome_dirs:
            logger.info(f"No Chrome data found for {package_name}")
            return result

        for chrome_dir in chrome_dirs:
            self._scan_chrome_dir(chrome_dir, result)

        if result.suspicious_visits:
            result.threat_level = "SUSPICIOUS"
            if len(result.suspicious_visits) >= 5:
                result.threat_level = "CRITICAL"
            logger.warning(
                f"Browser forensics: {len(result.suspicious_visits)} suspicious URLs "
                f"({result.total_visits} total visits)"
            )
        return result

    def _find_chrome_dirs(self, dump_dir: Path, package_name: str) -> list[Path]:
        """Find Chrome data directories in the dump."""
        candidates = []

        # Direct path
        direct = dump_dir / package_name
        if direct.exists():
            candidates.append(direct)

        # Searched path patterns
        for pattern in [
            f"**/{package_name}",
            f"**/app_webview",
            f"**/databases",
        ]:
            for d in dump_dir.glob(pattern):
                if d.is_dir() and any(f.suffix == "" for f in d.iterdir() if f.is_file()):
                    candidates.append(d)

        # Deduplicate by checking for SQLite files
        unique = set()
        result_dirs = []
        for d in candidates:
            db_files = list(d.rglob("*.db")) + list(d.rglob("Cookies")) + list(d.rglob("History"))
            if db_files:
                key = str(d.resolve())
                if key not in unique:
                    unique.add(key)
                    result_dirs.append(d)

        return result_dirs

    def _scan_chrome_dir(self, chrome_dir: Path, result: BrowserForensicsResult):
        """Scan a single Chrome data directory."""
        # Find all SQLite files
        for db_file in chrome_dir.rglob("*"):
            if not db_file.is_file():
                continue
            try:
                conn = sqlite3.connect(str(db_file))
                cursor = conn.cursor()

                # Get table names
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = {row[0] for row in cursor.fetchall()}

                if "urls" in tables:
                    self._parse_history(conn, result)
                if "logins" in tables:
                    self._parse_logins(conn, result)
                if "cookies" in tables:
                    self._parse_cookies(conn, result)

                conn.close()
            except Exception:
                continue

        if not result.db_path:
            result.db_path = str(chrome_dir)

    def _parse_history(self, conn: sqlite3.Connection, result: BrowserForensicsResult):
        """Parse Chrome History database."""
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 500"
            )
            for row in cursor.fetchall():
                url, title, visit_count, last_visit = row
                visit = BrowserVisit(
                    url=url or "",
                    title=title or "",
                    visit_count=visit_count or 0,
                    last_visit_time=str(last_visit or ""),
                )

                # Check for suspicious URLs
                for pattern in self._suspicious_patterns:
                    if pattern.search(url or ""):
                        visit.is_suspicious = True
                        visit.suspicious_reason = f"Matches suspicious pattern"
                        result.suspicious_visits.append(visit.to_dict())
                        break

                result.visits.append(visit.to_dict())
                result.total_visits += 1
        except Exception as e:
            logger.debug(f"History parse failed: {e}")

    def _parse_logins(self, conn: sqlite3.Connection, result: BrowserForensicsResult):
        """Parse Chrome Login Data database."""
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT origin_url, username_value, length(password_value), date_created, blacklisted_by_user "
                "FROM logins ORDER BY date_created DESC LIMIT 100"
            )
            for row in cursor.fetchall():
                login = BrowserLogin(
                    origin_url=row[0] or "",
                    username_value=row[1] or "",
                    password_length=row[2] or 0,
                    date_created=str(row[3] or ""),
                    blacklisted=bool(row[4]),
                )
                result.logins.append(login.to_dict())
                result.total_logins += 1
        except Exception as e:
            logger.debug(f"Login parse failed: {e}")

    def _parse_cookies(self, conn: sqlite3.Connection, result: BrowserForensicsResult):
        """Parse Chrome Cookies database."""
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT host_key, name, path, expires_utc, is_secure, is_httponly, samesite "
                "FROM cookies ORDER BY expires_utc DESC LIMIT 200"
            )
            for row in cursor.fetchall():
                cookie = BrowserCookie(
                    host_key=row[0] or "",
                    name=row[1] or "",
                    path=row[2] or "",
                    expires_utc=str(row[3] or ""),
                    is_secure=bool(row[4]),
                    is_httponly=bool(row[5]),
                    samesite=str(row[6] or ""),
                )

                # Flag cookies to suspicious domains
                for pattern in self._suspicious_patterns:
                    if pattern.search(cookie.host_key):
                        cookie.is_suspicious = True
                        break

                result.cookies.append(cookie.to_dict())
                result.total_cookies += 1
        except Exception as e:
            logger.debug(f"Cookie parse failed: {e}")

    def extract_from_live_device(self, serial: str, package_name: str = "com.android.chrome") -> BrowserForensicsResult:
        """Pull Chrome databases from a live device via ADB."""
        from core import run_adb

        result = BrowserForensicsResult(package_name=package_name)

        # Get Chrome data dir
        success, output = run_adb(
            f"-s {serial} shell run-as {package_name} ls /data/data/{package_name}/databases/",
            timeout=10,
        )
        if not success or not output:
            logger.info(f"Cannot access Chrome databases for {package_name}")
            return result

        # Pull each database
        import tempfile
        with tempfile.TemporaryDirectory() as tmp_dir:
            for db_name in ["History", "Cookies", "Login Data", "Web Data"]:
                remote = f"/data/data/{package_name}/databases/{db_name}"
                local = Path(tmp_dir) / db_name.replace(" ", "_")
                run_adb(f"-s {serial} pull {remote} {local}", timeout=15)

                if local.exists():
                    try:
                        conn = sqlite3.connect(str(local))
                        tables = {row[0] for row in conn.execute(
                            "SELECT name FROM sqlite_master WHERE type='table'"
                        ).fetchall()}
                        if "urls" in tables:
                            self._parse_history(conn, result)
                        if "logins" in tables:
                            self._parse_logins(conn, result)
                        if "cookies" in tables:
                            self._parse_cookies(conn, result)
                        conn.close()
                    except Exception:
                        continue

        if result.suspicious_visits:
            result.threat_level = "SUSPICIOUS"
        return result
