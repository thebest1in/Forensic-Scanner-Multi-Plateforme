import json
import time
import sqlite3
import threading
from pathlib import Path

from core import logger


DB_PATH = Path(__file__).parent / "rules" / "scans.db"
_INIT_LOCK = threading.Lock()
_INITIALIZED_PATHS: set[str] = set()


def _get_conn() -> sqlite3.Connection:
    """Get a connection to the scans database."""
    DB_PATH.parent.mkdir(exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initialize the scans database schema."""
    db_key = str(DB_PATH.resolve())
    with _INIT_LOCK:
        if db_key in _INITIALIZED_PATHS:
            return
        _init_db_schema()
        _INITIALIZED_PATHS.add(db_key)


def _init_db_schema() -> None:
    conn = _get_conn()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_serial TEXT NOT NULL,
            timestamp_utc TEXT NOT NULL,
            verdict TEXT NOT NULL,
            risk_score INTEGER DEFAULT 0,
            artifact_count INTEGER DEFAULT 0,
            yara_match_count INTEGER DEFAULT 0,
            suspicious_ip_count INTEGER DEFAULT 0,
            package_count INTEGER DEFAULT 0,
            running_process_count INTEGER DEFAULT 0,
            battery_level TEXT DEFAULT '',
            fingerprint TEXT DEFAULT '',
            summary_json TEXT DEFAULT '{}'
        );

        CREATE TABLE IF NOT EXISTS fingerprints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            metric_name TEXT NOT NULL,
            metric_value TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        );

        CREATE INDEX IF NOT EXISTS idx_scans_serial ON scans(device_serial);
        CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp_utc);
        CREATE INDEX IF NOT EXISTS idx_fp_scan ON fingerprints(scan_id);
    """)
    conn.commit()
    conn.close()
    logger.info(f"Scans DB initialized: {DB_PATH.name}")


class ScanRecord:
    """A single scan record for database storage."""

    def __init__(self):
        self.device_serial: str = ""
        self.timestamp_utc: str = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
        self.verdict: str = "CLEAN"
        self.risk_score: int = 0
        self.artifact_count: int = 0
        self.yara_match_count: int = 0
        self.suspicious_ip_count: int = 0
        self.package_count: int = 0
        self.running_process_count: int = 0
        self.battery_level: str = ""
        self.fingerprint: str = ""
        self.summary_json: str = "{}"
        self.fingerprints: dict[str, str] = {}


def record_scan(record: ScanRecord) -> int:
    """Insert a scan record into the database. Returns the scan ID."""
    init_db()
    conn = _get_conn()
    cursor = conn.execute("""
        INSERT INTO scans (
            device_serial, timestamp_utc, verdict, risk_score,
            artifact_count, yara_match_count, suspicious_ip_count,
            package_count, running_process_count, battery_level,
            fingerprint, summary_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        record.device_serial, record.timestamp_utc, record.verdict,
        record.risk_score, record.artifact_count, record.yara_match_count,
        record.suspicious_ip_count, record.package_count,
        record.running_process_count, record.battery_level,
        record.fingerprint, record.summary_json,
    ))
    scan_id = cursor.lastrowid

    for name, value in record.fingerprints.items():
        conn.execute(
            "INSERT INTO fingerprints (scan_id, metric_name, metric_value) VALUES (?, ?, ?)",
            (scan_id, name, value),
        )

    conn.commit()
    conn.close()
    logger.info(f"Scan recorded: ID={scan_id}, verdict={record.verdict}")
    return scan_id


def get_history(device_serial: str, limit: int = 10) -> list[dict]:
    """Get recent scan history for a device."""
    init_db()
    conn = _get_conn()
    rows = conn.execute(
        "SELECT * FROM scans WHERE device_serial = ? ORDER BY id DESC LIMIT ?",
        (device_serial, limit),
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_latest_scan(device_serial: str) -> dict | None:
    """Get the most recent scan for a device."""
    init_db()
    conn = _get_conn()
    row = conn.execute(
        "SELECT * FROM scans WHERE device_serial = ? ORDER BY id DESC LIMIT 1",
        (device_serial,),
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def compute_delta(current: ScanRecord, device_serial: str) -> dict:
    """
    Compare current scan against the last scan for this device.
    Returns delta report with anomalies.
    """
    init_db()
    prev = get_latest_scan(device_serial)

    if not prev:
        return {
            "is_first_scan": True,
            "anomalies": [],
            "message": "First scan for this device — baseline established.",
        }

    anomalies = []

    # Package count delta
    if current.package_count > 0 and prev.get("package_count", 0) > 0:
        pkg_delta = current.package_count - prev["package_count"]
        if pkg_delta > 3:
            anomalies.append({
                "metric": "new_packages",
                "severity": "HIGH",
                "message": f"{pkg_delta} new packages installed since last scan",
                "previous": prev["package_count"],
                "current": current.package_count,
            })
        elif pkg_delta < -3:
            anomalies.append({
                "metric": "removed_packages",
                "severity": "MEDIUM",
                "message": f"{abs(pkg_delta)} packages removed since last scan",
                "previous": prev["package_count"],
                "current": current.package_count,
            })

    # Process count delta
    if current.running_process_count > 0 and prev.get("running_process_count", 0) > 0:
        proc_delta = current.running_process_count - prev["running_process_count"]
        if proc_delta > 5:
            anomalies.append({
                "metric": "new_processes",
                "severity": "HIGH",
                "message": f"{proc_delta} new background processes detected",
                "previous": prev["running_process_count"],
                "current": current.running_process_count,
            })

    # Verdict change
    if prev.get("verdict") == "CLEAN" and current.verdict != "CLEAN":
        anomalies.append({
            "metric": "verdict_degraded",
            "severity": "CRITICAL",
            "message": f"Device status degraded: CLEAN -> {current.verdict}",
            "previous": prev["verdict"],
            "current": current.verdict,
        })

    # YARA match delta
    if current.yara_match_count > 0 and prev.get("yara_match_count", 0) == 0:
        anomalies.append({
            "metric": "new_yara_matches",
            "severity": "CRITICAL",
            "message": f"New YARA matches detected: {current.yara_match_count}",
            "previous": 0,
            "current": current.yara_match_count,
        })

    # Risk score delta
    risk_delta = current.risk_score - prev.get("risk_score", 0)
    if risk_delta > 20:
        anomalies.append({
            "metric": "risk_score_spike",
            "severity": "HIGH",
            "message": f"Risk score increased by {risk_delta} points",
            "previous": prev.get("risk_score", 0),
            "current": current.risk_score,
        })

    return {
        "is_first_scan": False,
        "previous_scan_id": prev.get("id"),
        "previous_timestamp": prev.get("timestamp_utc"),
        "anomalies": anomalies,
        "message": f"Compared against scan #{prev.get('id', '?')} from {prev.get('timestamp_utc', '?')}",
    }


def build_scan_record(
    device_serial: str,
    verdict: str,
    extracted_files: dict,
    yara_matches: list,
    suspicious_ips: list,
    risk_score: int = 0,
    package_count: int = 0,
    process_count: int = 0,
) -> ScanRecord:
    """Build a ScanRecord from analysis results."""
    record = ScanRecord()
    record.device_serial = device_serial
    record.verdict = verdict
    record.risk_score = risk_score
    record.artifact_count = len(extracted_files)
    record.yara_match_count = len(yara_matches)
    record.suspicious_ip_count = len(suspicious_ips)
    record.package_count = package_count
    record.running_process_count = process_count

    # Build fingerprints from extracted data
    if "third_party_apps" in extracted_files:
        try:
            content = extracted_files["third_party_apps"].read_text(encoding="utf-8", errors="replace")
            record.fingerprints["package_hash"] = str(hash(content))
        except Exception:
            pass

    if "processes" in extracted_files:
        try:
            content = extracted_files["processes"].read_text(encoding="utf-8", errors="replace")
            record.fingerprints["process_hash"] = str(hash(content))
        except Exception:
            pass

    record.fingerprint = f"artifacts={len(extracted_files)}|yara={len(yara_matches)}|ips={len(suspicious_ips)}"
    record.summary_json = json.dumps({
        "verdict": verdict,
        "risk_score": risk_score,
        "yara_matches": [m["rule"] for m in yara_matches],
        "suspicious_ips": suspicious_ips,
    })

    return record
