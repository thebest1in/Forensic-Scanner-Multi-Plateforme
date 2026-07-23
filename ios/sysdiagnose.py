"""iOS sysdiagnose handler.

Manages sysdiagnose tar.gz collection, extraction, and analysis.
"""
from __future__ import annotations

import tarfile
from pathlib import Path
from typing import Any

from core import logger


def extract_sysdiagnose(sysdiagnose_path: Path, output_dir: Path) -> Path | None:
    """Extract a sysdiagnose tar.gz archive.

    Returns the extracted directory path, or None on failure.
    """
    if not sysdiagnose_path.exists():
        logger.warning(f"Sysdiagnose file not found: {sysdiagnose_path}")
        return None

    try:
        with tarfile.open(sysdiagnose_path, "r:gz") as tar:
            members = tar.getmembers()
            logger.info(f"Sysdiagnose archive contains {len(members)} files")
            tar.extractall(output_dir)
        logger.success(f"Sysdiagnose extracted to {output_dir.name}")
        return output_dir
    except tarfile.TarError as e:
        logger.error(f"Failed to extract sysdiagnose: {e}")
        return None
    except Exception as e:
        logger.error(f"Sysdiagnose extraction error: {e}")
        return None


def parse_sysdiagnose(sysdiagnose_dir: Path) -> dict[str, Any]:
    """Parse key files from an extracted sysdiagnose directory.

    Looks for:
    - WiFi logs
    - Bluetooth logs
    - System logs
    - Power logs
    - Panic logs
    """
    results = {
        "wifi_logs": [],
        "bluetooth_logs": [],
        "system_logs": [],
        "power_logs": [],
        "panic_logs": [],
        "total_files": 0,
    }

    if not sysdiagnose_dir.exists():
        return results

    for file_path in sysdiagnose_dir.rglob("*"):
        if not file_path.is_file():
            continue
        results["total_files"] += 1
        name_lower = file_path.name.lower()
        if "wifi" in name_lower or "wlan" in name_lower:
            results["wifi_logs"].append(str(file_path))
        elif "bluetooth" in name_lower or "bt" in name_lower:
            results["bluetooth_logs"].append(str(file_path))
        elif "panic" in name_lower:
            results["panic_logs"].append(str(file_path))
        elif "power" in name_lower or "battery" in name_lower:
            results["power_logs"].append(str(file_path))
        elif name_lower.endswith((".log", ".txt", ".xml")):
            results["system_logs"].append(str(file_path))

    logger.info(
        f"Sysdiagnose parse: {results['total_files']} files, "
        f"{len(results['wifi_logs'])} wifi, "
        f"{len(results['system_logs'])} system logs"
    )
    return results


def analyze_panic_logs(panic_logs: list[str]) -> list[dict[str, Any]]:
    """Analyze kernel panic logs for suspicious patterns."""
    findings = []
    for log_path in panic_logs:
        try:
            content = Path(log_path).read_text(encoding="utf-8", errors="replace")
            # Check for signs of exploit attempts
            if "kernel_task" in content and "panic" in content.lower():
                findings.append({
                    "type": "KERNEL_PANIC",
                    "severity": "MEDIUM",
                    "file": log_path,
                    "evidence": "Kernel panic detected — may indicate exploit attempt",
                })
            if "sandbox" in content.lower() and "denied" in content.lower():
                findings.append({
                    "type": "SANDBOX_VIOLATION",
                    "severity": "LOW",
                    "file": log_path,
                    "evidence": "Sandbox violations found in panic log",
                })
        except Exception:
            pass
    return findings
