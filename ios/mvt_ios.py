"""MVT iOS adapter.

Integrates MVT (Mobile Verification Toolkit) iOS analysis for
spyware detection and IOC correlation on iOS backups.
"""
from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from core import logger


@dataclass
class MVTResult:
    """Result from an MVT iOS scan."""
    tool_name: str = "mvt_ios"
    threat_level: str = "clean"
    indicators_found: int = 0
    indicators: list[dict] = None
    errors: list[str] = None
    output_dir: str = ""

    def __post_init__(self):
        if self.indicators is None:
            self.indicators = []
        if self.errors is None:
            self.errors = []

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_tool": self.tool_name,
            "threat_level": self.threat_level,
            "indicators_found": self.indicators_found,
            "indicators": self.indicators,
            "errors": self.errors,
            "output_dir": self.output_dir,
            "classification": "ioc_match" if self.indicators_found > 0 else "clean",
            "authoritative": self.indicators_found > 0,
            "confidence": 0.9 if self.indicators_found > 0 else 0.0,
        }


def check_mvt_ios_available() -> bool:
    """Check if mvt-ios is available on the system."""
    try:
        result = subprocess.run(
            ["mvt-ios", "--help"],
            capture_output=True,
            timeout=10,
            creationflags=(
                subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
            ),
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
    except Exception:
        return False


def scan_ios_backup(
    backup_dir: Path,
    output_dir: Path,
    ioc_file: Path | None = None,
    config: dict | None = None,
) -> MVTResult:
    """Run MVT iOS check-backup against an iOS backup.

    Args:
        backup_dir: Path to the iOS backup directory
        output_dir: Directory to write MVT results
        ioc_file: Optional IOC file (CSV/STIX) for matching
        config: Optional config overrides for MVT command

    Returns:
        MVTResult with findings
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    result = MVTResult(output_dir=str(output_dir))

    # Check if mvt-ios is available
    if not check_mvt_ios_available():
        result.errors.append("mvt-ios not found on PATH")
        result.threat_level = "unavailable"
        return result

    # Build mvt-ios command
    cmd = [
        "mvt-ios", "check-backup",
        "--output", str(output_dir),
    ]

    # Only add --ioc if provided and file exists
    if ioc_file and ioc_file.exists():
        cmd.extend(["--ioc", str(ioc_file)])

    # Add backup path as last argument
    cmd.append(str(backup_dir))

    # Apply config overrides
    if config:
        if config.get("no_stix"):
            cmd.append("--no-stix")

    logger.info(f"Running MVT iOS: {' '.join(cmd[:6])}...")

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=300,
            creationflags=(
                subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
            ),
        )
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""

        if proc.returncode != 0:
            result.errors.append(f"mvt-ios exited with code {proc.returncode}")
            if stderr:
                result.errors.append(stderr[:500])
            # Still try to parse partial output
            if "detected" in stdout.lower() or "indicator" in stdout.lower():
                result.threat_level = "high"
            else:
                result.threat_level = "error"
            return result

        # Parse MVT output for indicators
        indicators = _parse_mvt_output(output_dir)
        result.indicators = indicators
        result.indicators_found = len(indicators)

        if indicators:
            result.threat_level = "critical" if len(indicators) > 5 else "high"
            logger.warning(f"MVT iOS: {len(indicators)} indicators found")
        else:
            result.threat_level = "clean"
            logger.info("MVT iOS: No indicators found")

    except subprocess.TimeoutExpired:
        result.errors.append("MVT iOS scan timed out after 300s")
        result.threat_level = "error"
    except Exception as e:
        result.errors.append(f"MVT iOS error: {e}")
        result.threat_level = "error"

    return result


def _parse_mvt_output(output_dir: Path) -> list[dict]:
    """Parse MVT iOS output files for indicators."""
    indicators = []

    # MVT writes results to the output directory
    # Look for detected indicators in MVT result files
    for result_file in output_dir.rglob("*"):
        if not result_file.is_file():
            continue
        if result_file.suffix in (".csv", ".json"):
            try:
                content = result_file.read_text(encoding="utf-8", errors="replace")
                if "indicator" in content.lower() or "detected" in content.lower():
                    # Parse indicator entries
                    for line in content.splitlines():
                        line = line.strip()
                        if line and not line.startswith("#") and not line.startswith("source"):
                            parts = line.split(",") if "," in line else [line]
                            indicators.append({
                                "indicator": parts[0] if parts else line,
                                "source_file": result_file.name,
                                "type": "unknown",
                            })
            except Exception:
                pass

        # Also check for SQLite result databases
        if result_file.suffix == ".db":
            try:
                import sqlite3
                conn = sqlite3.connect(f"file:{result_file.as_posix()}?mode=ro", uri=True)
                try:
                    tables = [
                        row[0] for row in conn.execute(
                            "SELECT name FROM sqlite_master WHERE type='table'"
                        ).fetchall()
                    ]
                    for table in tables:
                        try:
                            rows = conn.execute(f"SELECT * FROM {table}").fetchall()
                            for row in rows:
                                indicators.append({
                                    "indicator": str(row[0]) if row else "",
                                    "source_file": result_file.name,
                                    "table": table,
                                    "type": "db_record",
                                })
                        except Exception:
                            pass
                finally:
                    conn.close()
            except Exception:
                pass

    return indicators


def normalize_mvt_findings(
    mvt_result: MVTResult,
    artifact_name: str = "ios_backup",
) -> list[dict[str, Any]]:
    """Normalize MVT findings into the canonical IOC schema."""
    normalized = []
    for indicator in mvt_result.indicators:
        normalized.append({
            "source_tool": "mvt_ios",
            "classification": "ioc_match",
            "authoritative": True,
            "confidence": 0.9,
            "artifact": artifact_name,
            "indicator_type": indicator.get("type", "unknown"),
            "indicator": indicator.get("indicator", ""),
            "source_file": indicator.get("source_file", ""),
        })
    return normalized
