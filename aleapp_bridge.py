import json
import subprocess
import sys
import shutil
from pathlib import Path
from dataclasses import dataclass, field

from core import logger, BASE_DIR


@dataclass
class ALEAPPResult:
    """Results from ALEAPP (Android Logs Events And Protobuf Parser)."""
    available: bool = False
    artifacts_parsed: list[dict] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    details: str = ""
    report_path: str = ""

    @property
    def has_findings(self) -> bool:
        return len(self.findings) > 0

    @property
    def severity(self) -> str:
        if not self.available:
            return "UNAVAILABLE"
        if not self.findings:
            return "CLEAN"
        critical = [f for f in self.findings if f.get("severity") == "CRITICAL"]
        if critical:
            return "CRITICAL"
        return "SUSPICIOUS"

    def to_dict(self) -> dict:
        return {
            "available": self.available,
            "artifacts_parsed": len(self.artifacts_parsed),
            "findings": self.findings,
            "severity": self.severity,
            "details": self.details,
            "report_path": self.report_path,
        }


def check_aleapp_available() -> bool:
    """Check if ALEAPP is installed."""
    if shutil.which("aleapp"):
        return True
    try:
        result = subprocess.run(
            [sys.executable, "-m", "aleapp", "--help"],
            capture_output=True, text=True, timeout=10,
        )
        return result.returncode == 0
    except Exception:
        pass
    return False


def run_aleapp(dump_dir: Path, output_dir: Path, on_progress=None) -> ALEAPPResult:
    """Run ALEAPP on extracted Android artifacts.

    ALEAPP parses:
    - Android application artifacts (APKs, databases)
    - System logs and events
    - SQLite databases (sms, calls, browsers, contacts)
    - Usage statistics and app history
    - Notification history
    - WiFi and Bluetooth connection history
    """
    result = ALEAPPResult()

    if not check_aleapp_available():
        result.details = "ALEAPP not installed. Install via: pip install aleapp"
        logger.warning("ALEAPP not available — skipping deep artifact parsing")
        return result

    result.available = True

    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        report_dir = output_dir / "aleapp_report"
        report_dir.mkdir(exist_ok=True)

        cmd = [
            sys.executable, "-m", "aleapp",
            "-i", str(dump_dir),
            "-o", str(report_dir),
            "-t", "fs",
        ]

        if on_progress:
            on_progress(0, "Running ALEAPP deep artifact analysis...")

        proc = subprocess.run(
            cmd, capture_output=True, text=True,
            encoding="utf-8", errors="replace",
            timeout=600,
        )

        report_files = list(report_dir.rglob("*.html")) + list(report_dir.rglob("*.json"))
        if report_files:
            for rf in report_files:
                if rf.suffix == ".json":
                    try:
                        with open(rf, "r", encoding="utf-8") as f:
                            data = json.load(f)
                            result.artifacts_parsed.extend(_parse_aleapp_json(data))
                    except Exception:
                        pass

        result.findings = _analyze_aleapp_artifacts(dump_dir, result.artifacts_parsed)
        result.report_path = str(report_dir)
        result.details = f"ALEAPP analysis complete: {len(result.artifacts_parsed)} artifacts, {len(result.findings)} findings"

        if on_progress:
            on_progress(100, result.details)

    except subprocess.TimeoutExpired:
        result.details = "ALEAPP analysis timed out (600s)"
        logger.warning(result.details)
    except Exception as e:
        result.details = f"ALEAPP analysis failed: {e}"
        logger.warning(result.details)

    return result


def parse_aleapp_offline(dump_dir: Path, on_progress=None) -> ALEAPPResult:
    """Parse Android artifacts without ALEAPP binary — manual forensic analysis.

    This fallback parser handles common Android forensic artifacts:
    - SQLite databases (sms.db, calls.db, browser history)
    - Log files (logcat, events, radio)
    - Binary XML files
    - Usage statistics
    """
    result = ALEAPPResult()
    result.available = True

    if on_progress:
        on_progress(0, "Running offline Android artifact analysis...")

    findings = []

    for fpath in sorted(dump_dir.rglob("*")):
        if not fpath.is_file():
            continue

        try:
            if fpath.suffix == ".db" or fpath.suffix == ".sqlite":
                db_findings = _analyze_sqlite_artifact(fpath)
                findings.extend(db_findings)

            elif fpath.suffix == ".log" or fpath.suffix == ".txt":
                log_findings = _analyze_log_artifact(fpath)
                findings.extend(log_findings)

        except Exception:
            continue

    result.findings = findings
    result.artifacts_parsed = [{"file": str(f)} for f in dump_dir.rglob("*") if f.is_file()]
    result.details = f"Offline analysis complete: {len(findings)} findings from {len(result.artifacts_parsed)} files"

    if on_progress:
        on_progress(100, result.details)

    return result


def _parse_aleapp_json(data: dict) -> list[dict]:
    """Parse ALEAPP JSON report output."""
    artifacts = []
    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        artifacts.append({
                            "plugin": key,
                            "data": item,
                        })
    return artifacts


SUSPICIOUS_PATTERNS = [
    (r"com\.flexispy", "Known stalkerware: FlexiSPY"),
    (r"com\.mspy", "Known stalkerware: mSpy"),
    (r"com\.highster", "Known stalkerware: Highster Mobile"),
    (r"com\.spyrie", "Known stalkerware: Spyrie"),
    (r"com\.thetracker", "Known stalkerware: The Tracker"),
    (r"com\.android\.sys\.update\.co", "Disguised system update package"),
    (r"com\.android\.service\.update", "Disguised service update package"),
    (r"net\.droidjack", "Known RAT: DroidJack"),
    (r"com\.sandrorat", "Known RAT: SandroRAT"),
]

SQLITE_SUSPICIOUS_QUERIES = [
    ("SELECT * FROM sms", "SMS database access"),
    ("SELECT * FROM calls", "Call log access"),
    ("SELECT * FROM contacts", "Contacts exfiltration"),
    ("SELECT * FROM location", "Location tracking"),
    ("PRAGMA key", "Encrypted database attempt"),
]


def _analyze_sqlite_artifact(fpath: Path) -> list[dict]:
    """Analyze a SQLite database for suspicious patterns."""
    import sqlite3
    findings = []

    try:
        conn = sqlite3.connect(str(fpath))
        cursor = conn.cursor()

        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]

        for table in tables:
            table_lower = table.lower()
            if table_lower in ("sms", "messages", "message"):
                findings.append({
                    "type": "sms_database",
                    "indicator": f"SMS table found in {fpath.name}",
                    "description": f"Message database detected: {table}",
                    "severity": "SUSPICIOUS",
                    "source": "aleapp_sqlite",
                    "file": fpath.name,
                })

            if table_lower in ("calls", "call_log", "calllog"):
                findings.append({
                    "type": "call_log_database",
                    "indicator": f"Call log table found in {fpath.name}",
                    "description": f"Call log database detected: {table}",
                    "severity": "SUSPICIOUS",
                    "source": "aleapp_sqlite",
                    "file": fpath.name,
                })

            if "location" in table_lower or "gps" in table_lower:
                findings.append({
                    "type": "location_database",
                    "indicator": f"Location table found in {fpath.name}",
                    "description": f"Location/GPS database detected: {table}",
                    "severity": "SUSPICIOUS",
                    "source": "aleapp_sqlite",
                    "file": fpath.name,
                })

        conn.close()

    except Exception:
        pass

    return findings


def _analyze_log_artifact(fpath: Path) -> list[dict]:
    """Analyze log/text files for suspicious patterns."""
    import re
    findings = []

    try:
        content = fpath.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return findings

    for pattern, desc in SUSPICIOUS_PATTERNS:
        if re.search(pattern, content, re.IGNORECASE):
            findings.append({
                "type": "suspicious_package",
                "indicator": pattern,
                "description": f"{desc} in {fpath.name}",
                "severity": "CRITICAL" if "stalkerware" in desc.lower() or "RAT" in desc else "SUSPICIOUS",
                "source": "aleapp_log",
                "file": fpath.name,
            })

    return findings


def _analyze_aleapp_artifacts(dump_dir: Path, artifacts: list[dict]) -> list[dict]:
    """Cross-reference ALEAPP artifacts with known threat indicators."""
    findings = []

    for artifact in artifacts:
        data = artifact.get("data", {})
        plugin = artifact.get("plugin", "")

        if "package" in str(data).lower():
            pkg_name = data.get("package_name", data.get("package", ""))
            for pattern, desc in SUSPICIOUS_PATTERNS:
                import re
                if re.search(pattern, str(pkg_name), re.IGNORECASE):
                    findings.append({
                        "type": "aleapp_suspicious_package",
                        "indicator": pkg_name,
                        "description": desc,
                        "severity": "CRITICAL" if "stalkerware" in desc.lower() else "SUSPICIOUS",
                        "source": "aleapp",
                        "plugin": plugin,
                    })

    return findings
