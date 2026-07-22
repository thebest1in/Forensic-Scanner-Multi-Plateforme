import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

from core import ADB_BINARY, logger

# ============================================================
# OPENMF BRIDGE - Calls OpenMF collector.py for data extraction
# ============================================================

OPENMF_DIR = Path(r"C:\Users\imadfdl\forensic_tools\OpenMF")


@dataclass
class OpenMFResult:
    """Results from OpenMF data extraction."""
    available: bool = False
    has_root: bool = False
    device_info: dict = field(default_factory=dict)
    accounts: list[dict] = field(default_factory=list)
    contacts_count: int = 0
    call_logs_count: int = 0
    sms_count: int = 0
    whatsapp_count: int = 0
    facebook_count: int = 0
    browser_count: int = 0
    bluetooth_count: int = 0
    location_count: int = 0
    media_count: int = 0
    extracted_dbs: list[str] = field(default_factory=list)
    session_dir: str = ""
    details: str = ""

    @property
    def total_extracted(self) -> int:
        return (
            self.contacts_count + self.call_logs_count + self.sms_count
            + self.whatsapp_count + self.facebook_count + self.browser_count
            + self.bluetooth_count + self.location_count + self.media_count
        )

    @property
    def severity(self) -> str:
        if not self.available:
            return "UNAVAILABLE"
        if not self.has_root:
            return "ROOT_REQUIRED"
        return "OK"

    def to_dict(self) -> dict:
        return {
            "available": self.available,
            "has_root": self.has_root,
            "device_info": self.device_info,
            "accounts": self.accounts,
            "contacts": self.contacts_count,
            "call_logs": self.call_logs_count,
            "sms": self.sms_count,
            "whatsapp": self.whatsapp_count,
            "facebook": self.facebook_count,
            "browser": self.browser_count,
            "bluetooth": self.bluetooth_count,
            "location": self.location_count,
            "media": self.media_count,
            "total_extracted": self.total_extracted,
            "extracted_dbs": self.extracted_dbs[:50],
            "session_dir": self.session_dir,
            "severity": self.severity,
            "details": self.details,
        }


def check_openmf_available() -> bool:
    """Check if OpenMF is cloned and collector.py exists."""
    collector = OPENMF_DIR / "collector.py"
    return collector.exists()


def _check_root_access() -> bool:
    """Check if device has root access."""
    try:
        result = subprocess.run(
            [ADB_BINARY, "shell", "id"],
            capture_output=True, text=True, timeout=10,
        )
        if "root" in result.stdout:
            return True
        result = subprocess.run(
            [ADB_BINARY, "shell", "su", "-c", "id"],
            capture_output=True, text=True, timeout=10,
        )
        return "root" in result.stdout
    except Exception:
        return False


def _get_device_info() -> dict:
    """Get basic device info via ADB."""
    info = {}
    props = {
        "manufacturer": "ro.product.manufacturer",
        "model": "ro.product.model",
        "serial": "ro.serialno",
        "android_version": "ro.build.version.release",
        "sdk": "ro.build.version.sdk",
        "security_patch": "ro.build.version.security_patch",
        "build_type": "ro.build.type",
    }
    for key, prop in props.items():
        try:
            result = subprocess.run(
                [ADB_BINARY, "shell", "getprop", prop],
                capture_output=True, text=True, timeout=5,
            )
            info[key] = result.stdout.strip()
        except Exception:
            info[key] = "unknown"
    return info


def _run_openmf_collector(
    options: list[str], session_name: str
) -> tuple[bool, str]:
    """Run OpenMF collector.py with given options."""
    collector_script = OPENMF_DIR / "collector.py"
    if not collector_script.exists():
        return False, "OpenMF collector.py not found"

    cmd = [
        sys.executable, str(collector_script),
        "-o", *options,
        "-sn", session_name,
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True, text=True,
            encoding="utf-8", errors="replace",
            timeout=300,
            cwd=str(OPENMF_DIR),
        )
        output = result.stdout + result.stderr
        return result.returncode == 0, output
    except subprocess.TimeoutExpired:
        return False, "OpenMF extraction timed out (300s)"
    except Exception as e:
        return False, f"OpenMF error: {e}"


def _count_extracted_records(session_dir: Path) -> dict[str, int]:
    """Count records in extracted SQLite databases."""
    counts = {
        "contacts": 0, "call_logs": 0, "sms": 0,
        "whatsapp": 0, "facebook": 0, "browser": 0,
        "bluetooth": 0, "location": 0, "media": 0,
    }

    db_dir = session_dir / "db"
    if not db_dir.exists():
        return counts

    import sqlite3
    for db_file in db_dir.glob("*.db"):
        try:
            conn = sqlite3.connect(str(db_file))
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0].lower() for row in cursor.fetchall()]

            for table in tables:
                if "contact" in table:
                    cursor.execute(f"SELECT COUNT(*) FROM [{table}]")
                    counts["contacts"] += cursor.fetchone()[0]
                elif "call" in table:
                    cursor.execute(f"SELECT COUNT(*) FROM [{table}]")
                    counts["call_logs"] += cursor.fetchone()[0]
                elif "sms" in table or "message" in table:
                    cursor.execute(f"SELECT COUNT(*) FROM [{table}]")
                    counts["sms"] += cursor.fetchone()[0]
                elif "whatsapp" in table or "wa" in table:
                    cursor.execute(f"SELECT COUNT(*) FROM [{table}]")
                    counts["whatsapp"] += cursor.fetchone()[0]
                elif "facebook" in table or "fb" in table:
                    cursor.execute(f"SELECT COUNT(*) FROM [{table}]")
                    counts["facebook"] += cursor.fetchone()[0]
                elif "browser" in table or "history" in table:
                    cursor.execute(f"SELECT COUNT(*) FROM [{table}]")
                    counts["browser"] += cursor.fetchone()[0]
                elif "bluetooth" in table:
                    cursor.execute(f"SELECT COUNT(*) FROM [{table}]")
                    counts["bluetooth"] += cursor.fetchone()[0]
                elif "location" in table or "gps" in table:
                    cursor.execute(f"SELECT COUNT(*) FROM [{table}]")
                    counts["location"] += cursor.fetchone()[0]
                elif "media" in table or "image" in table or "video" in table:
                    cursor.execute(f"SELECT COUNT(*) FROM [{table}]")
                    counts["media"] += cursor.fetchone()[0]

            conn.close()
        except Exception:
            continue

    return counts


def extract_data(
    session_name: str = "forensic_scan",
    on_progress=None,
) -> OpenMFResult:
    """Run OpenMF data extraction on rooted device.

    Args:
        session_name: Session identifier for this extraction
        on_progress: Progress callback(percent, message)

    Returns:
        OpenMFResult with extracted data
    """
    result = OpenMFResult()

    if not check_openmf_available():
        result.details = "OpenMF not found. Clone from: https://github.com/scorelab/OpenMF"
        logger.warning("OpenMF not available")
        return result

    result.available = True

    if on_progress:
        on_progress(5, "Checking root access...")

    if not _check_root_access():
        result.has_root = False
        result.details = "Root access required for OpenMF extraction"
        logger.warning("OpenMF requires root — skipping")
        return result

    result.has_root = True

    if on_progress:
        on_progress(10, "Getting device info...")

    result.device_info = _get_device_info()

    if on_progress:
        on_progress(20, "Running OpenMF collector (all databases)...")

    success, output = _run_openmf_collector(
        ["all"], session_name
    )

    if not success:
        result.details = f"OpenMF extraction failed: {output[:500]}"
        logger.warning(result.details)
        return result

    session_dir = OPENMF_DIR / "data" / session_name
    result.session_dir = str(session_dir)

    if on_progress:
        on_progress(70, "Counting extracted records...")

    if session_dir.exists():
        db_dir = session_dir / "db"
        if db_dir.exists():
            result.extracted_dbs = [f.name for f in db_dir.glob("*.db")]

        counts = _count_extracted_records(session_dir)
        result.contacts_count = counts.get("contacts", 0)
        result.call_logs_count = counts.get("call_logs", 0)
        result.sms_count = counts.get("sms", 0)
        result.whatsapp_count = counts.get("whatsapp", 0)
        result.facebook_count = counts.get("facebook", 0)
        result.browser_count = counts.get("browser", 0)
        result.bluetooth_count = counts.get("bluetooth", 0)
        result.location_count = counts.get("location", 0)
        result.media_count = counts.get("media", 0)

    result.details = (
        f"OpenMF extraction complete: {len(result.extracted_dbs)} databases, "
        f"{result.total_extracted} records"
    )

    if on_progress:
        on_progress(100, result.details)

    return result
