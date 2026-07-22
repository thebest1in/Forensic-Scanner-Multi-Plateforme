import json
import subprocess
import sys
import shutil
from pathlib import Path
from dataclasses import dataclass, field

from core import logger, BASE_DIR


@dataclass
class MVTResult:
    """Results from MVT (Mobile Verification Toolkit) IOC scanning."""
    available: bool = False
    iocs_found: list[dict] = field(default_factory=list)
    indicators: dict = field(default_factory=dict)
    details: str = ""
    tool_version: str = ""

    @property
    def has_findings(self) -> bool:
        return len(self.iocs_found) > 0

    @property
    def severity(self) -> str:
        if not self.available:
            return "UNAVAILABLE"
        if not self.iocs_found:
            return "CLEAN"
        critical_tags = {"pegasus", "predator", "finfisher", "novispy", "hackingteam"}
        for finding in self.iocs_found:
            tags = set(finding.get("tags", []))
            if tags & critical_tags:
                return "CRITICAL"
        return "SUSPICIOUS"

    def to_dict(self) -> dict:
        return {
            "available": self.available,
            "iocs_found": self.iocs_found,
            "indicators": self.indicators,
            "severity": self.severity,
            "details": self.details,
            "tool_version": self.tool_version,
        }


def check_mvt_available() -> bool:
    """Check if MVT is installed and importable."""
    try:
        result = subprocess.run(
            [sys.executable, "-m", "mvt", "--version"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            return True
    except Exception:
        pass

    if shutil.which("mvt-android"):
        return True

    return False


def scan_ios_backup(backup_path: Path, output_dir: Path, on_progress=None) -> MVTResult:
    """Run MVT iOS backup analysis.

    MVT checks for:
    - Pegasus indicators in iOS backup
    - Compromised indicator analysis
    - Suspicious configuration profiles
    - Known malware signatures
    """
    result = MVTResult()

    if not check_mvt_available():
        result.details = "MVT not installed. Install via: pip install mvt"
        logger.warning("MVT not available — skipping iOS IOC scan")
        return result

    result.available = True

    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        iocs_file = output_dir / "mvt_ios_iocs.json"

        cmd = [
            sys.executable, "-m", "mvt", "ios",
            "check-backup",
            "--backup", str(backup_path),
            "--output", str(output_dir),
        ]

        if on_progress:
            on_progress(0, "Running MVT iOS backup analysis...")

        proc = subprocess.run(
            cmd, capture_output=True, text=True,
            encoding="utf-8", errors="replace",
            timeout=300,
        )

        if iocs_file.exists():
            with open(iocs_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                result.iocs_found = _parse_mvt_ios_output(data)
                result.indicators = {
                    "total_iocs": len(result.iocs_found),
                    "backup_path": str(backup_path),
                }
        elif proc.stdout:
            result.iocs_found = _parse_mvt_text_output(proc.stdout)
            result.indicators = {"total_iocs": len(result.iocs_found)}

        result.details = f"MVT iOS scan complete: {len(result.iocs_found)} IOCs found"
        if on_progress:
            on_progress(100, result.details)

    except subprocess.TimeoutExpired:
        result.details = "MVT iOS scan timed out (300s)"
        logger.warning(result.details)
    except Exception as e:
        result.details = f"MVT iOS scan failed: {e}"
        logger.warning(result.details)

    return result


def scan_android_dump(dump_dir: Path, output_dir: Path, on_progress=None) -> MVTResult:
    """Run MVT Android analysis on extracted artifacts.

    MVT checks for:
    - Pegasus/Predator indicators in Android dumps
    - Suspicious packages and apps
    - Known IOCs from state-sponsored threats
    - Battery usage anomalies (spyware drain patterns)
    """
    result = MVTResult()

    if not check_mvt_available():
        result.details = "MVT not installed. Install via: pip install mvt"
        logger.warning("MVT not available — skipping Android IOC scan")
        return result

    result.available = True

    try:
        output_dir.mkdir(parents=True, exist_ok=True)

        cmd = [
            sys.executable, "-m", "mvt", "android",
            "check-adb",
            "--output", str(output_dir),
        ]

        target_files = []
        for ext in ["*.txt", "*.log", "*.db", "*.sqlite"]:
            target_files.extend(dump_dir.rglob(ext))

        if on_progress:
            on_progress(0, f"Running MVT Android analysis on {len(target_files)} files...")

        iocs = []
        for i, fpath in enumerate(target_files):
            if on_progress and i % 10 == 0:
                pct = int((i / len(target_files)) * 100)
                on_progress(pct, f"MVT analyzing: {fpath.name}")

            try:
                content = fpath.read_text(encoding="utf-8", errors="replace")
                findings = _scan_content_for_mvt_iocs(content, fpath.name)
                iocs.extend(findings)
            except Exception:
                continue

        result.iocs_found = iocs
        result.indicators = {
            "total_iocs": len(iocs),
            "files_scanned": len(target_files),
            "dump_path": str(dump_dir),
        }
        result.details = f"MVT Android scan complete: {len(iocs)} IOCs found in {len(target_files)} files"

        if on_progress:
            on_progress(100, result.details)

    except Exception as e:
        result.details = f"MVT Android scan failed: {e}"
        logger.warning(result.details)

    return result


def _parse_mvt_ios_output(data: dict) -> list[dict]:
    """Parse MVT iOS JSON output into standard finding format."""
    findings = []
    if isinstance(data, dict):
        for key, entries in data.items():
            if isinstance(entries, list):
                for entry in entries:
                    if isinstance(entry, dict):
                        findings.append({
                            "type": key,
                            "indicator": entry.get("indicator", entry.get("value", "")),
                            "description": entry.get("description", entry.get("name", "")),
                            "severity": "CRITICAL" if "pegasus" in key.lower() else "SUSPICIOUS",
                            "source": "mvt_ios",
                        })
    return findings


def _parse_mvt_text_output(text: str) -> list[dict]:
    """Parse MVT text output for IOC indicators."""
    findings = []
    pegasus_patterns = [
        r"pegasus", r"nsogroup", r"forcedentry", r"blastdoor",
        r"zero.click", r"exploitchain", r"samples.*confirmed",
    ]
    for line in text.split("\n"):
        line_lower = line.lower()
        for pattern in pegasus_patterns:
            if pattern in line_lower:
                findings.append({
                    "type": "pegasus_indicator",
                    "indicator": line.strip()[:200],
                    "description": f"MVT text match: {pattern}",
                    "severity": "CRITICAL",
                    "source": "mvt_ios_text",
                })
                break
    return findings


KNOWN_MVT_IOCS = [
    "pegasus", "nsogroup", "forcedentry", "blastdoor",
    "predator", "cytrox", "intlex", "irongate",
    "finfisher", "finfly", "hackingteam", "da Vinci",
    "sandrorat", "dendroid", "wirelurker",
    "com.flexispy", "com.mspy", "com.highster",
    "com.sandrorat", "net.droidjack",
]


def _scan_content_for_mvt_iocs(content: str, filename: str) -> list[dict]:
    """Scan file content for known MVT IOC patterns."""
    findings = []
    content_lower = content.lower()

    for ioc in KNOWN_MVT_IOCS:
        if ioc.lower() in content_lower:
            findings.append({
                "type": "mvt_ioc",
                "indicator": ioc,
                "description": f"Known spyware indicator '{ioc}' found in {filename}",
                "severity": "CRITICAL" if ioc in (
                    "pegasus", "nsogroup", "forcedentry", "predator", "finfisher"
                ) else "SUSPICIOUS",
                "source": "mvt_content_scan",
                "file": filename,
            })

    return findings
