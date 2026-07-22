"""Terminal-first launcher for Universal Forensic Scanner."""
from __future__ import annotations

import csv
import json
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

from analyzer import analyze, save_report
from archive_engine import ingest_archive
from core import run_adb
from extractor import run_extraction
from remediation_engine import analyze_remediation
from timeline import build_timeline
from version import REPORT_SCHEMA_VERSION, VERSION

ROOT = Path(__file__).resolve().parent


def _log(level: str, message: str) -> None:
    print(f"[{level}] {message}", flush=True)


# The core logger owns terminal output. The CLI does not register a second
# callback, which prevents every event from being printed twice.


def _progress(percent: float, message: str) -> None:
    print(f"[{percent:5.1f}%] {message}", flush=True)


def _write_summary(result, output_dir: Path, mode: str, scan_id: str, started: float) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    timeline_path = output_dir / "forensic_timeline.csv"
    event_count = 0
    if timeline_path.exists():
        with timeline_path.open(newline="", encoding="utf-8", errors="replace") as stream:
            event_count = max(0, sum(1 for _ in csv.reader(stream)) - 1)
    warnings = [
        name for name, status in result.tool_status.items()
        if status in {"unavailable", "error", "timed_out"}
    ]
    artifacts = [{"id": key, "path": str(path), "size_bytes": path.stat().st_size}
                 for key, path in getattr(result, "_cli_extracted", {}).items() if path.exists()]
    payload = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "application_version": VERSION,
        "scan_id": scan_id,
        "scan_mode": mode,
        "status": "COMPLETED_WITH_WARNINGS" if any(
            value in {"unavailable", "error"} for value in result.tool_status.values()
        ) else "COMPLETED",
        "started_at_utc": datetime.fromtimestamp(started, UTC).isoformat(),
        "completed_at_utc": datetime.now(UTC).isoformat(),
        "duration_seconds": round(time.time() - started, 3),
        "verdict": result.verdict,
        "risk_score": result.composite_risk_score,
        "risk_level": result.composite_risk_level,
        "summary": {"artifact_count": len(artifacts), "finding_count": len(result.matched_rules),
                    "authoritative_finding_count": sum(1 for f in result.matched_rules if f.get("authoritative", True)),
                    "timeline_event_count": event_count},
        "artifacts": artifacts,
        "findings": result.matched_rules,
        "events": [],
        "timeline": {"event_count": event_count, "csv_path": str(timeline_path), "preview": [], "statistics": {}},
        "outputs": {
            "canonical_json": str(output_dir / "scan_result.json"),
            "legacy_json": str(output_dir / "forensic_report.json"),
            "timeline_csv": str(timeline_path),
            "pdf": None,
            "csv_exports": [],
        },
        "tool_health": result.tool_status,
        "warnings": warnings,
        "errors": [],
        "limitations": ["CLEAN does not prove that the device is malware-free."],
    }
    path = output_dir / "scan_result.json"
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    temporary.replace(path)
    return path


def _run_analysis(
    extracted: dict[str, Path], output_dir: Path, mode: str, scan_id: str,
    full_tools: bool = False,
) -> int:
    started = time.time()
    output_dir.mkdir(parents=True, exist_ok=True)
    _log("INFO", f"Starting {mode} scan: {scan_id}")
    result = analyze(
        extracted_files=extracted,
        device_serial=scan_id,
        dump_dir=output_dir,
        on_progress=_progress,
        run_mvt=full_tools,
        run_aleapp=full_tools,
        run_capa=full_tools,
        run_apkid=full_tools,
        run_quark=full_tools,
        run_intel=full_tools,
        run_entropy=full_tools,
        run_browser=full_tools,
        run_correlation=True,
    )
    result._cli_extracted = extracted
    remediation = analyze_remediation(result)
    result._remediation = remediation.to_dict()
    report = save_report(result, output_dir)
    timeline_path = build_timeline(extracted, output_dir)
    summary = _write_summary(result, output_dir, mode, scan_id, started)
    _log("OK", f"JSON report: {summary}")
    _log("OK", f"Legacy report: {report}")
    if timeline_path:
        _log("OK", f"Timeline CSV: {timeline_path}")
    _log("RESULT", f"{result.verdict} — {result.composite_risk_score}/100 ({result.composite_risk_level})")
    _log("INFO", f"Tool health: {result.tool_status}")
    return 0


def run_live() -> int:
    ok, devices = run_adb("devices -l", timeout=10)
    if not ok:
        _log("ERROR", "ADB is not available or the device list command failed")
        return 1
    device_lines = [
        line for line in devices.splitlines()
        if len(line.split()) >= 2 and line.split()[1] == "device"
    ]
    if not device_lines:
        _log("ERROR", "No authorized Android device found over USB")
        return 1
    serial = device_lines[0].split()[0]
    _log("OK", f"Android device selected: {serial}")
    profile = input("Profile [triage/deep] (default triage): ").strip().lower() or "triage"
    if profile not in {"triage", "deep"}:
        _log("ERROR", "Invalid profile")
        return 2
    scan_id = f"CLI_LIVE_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}"
    output_dir = ROOT / "output" / scan_id
    _log("INFO", "Acquiring Android artifacts through ADB (read-only commands)...")
    extracted = run_extraction(serial, profile, _progress)
    if not extracted:
        _log("ERROR", "No artifacts were acquired")
        return 1
    _log("INFO", "All optional analyzers enabled for this Android Live scan")
    return _run_analysis(extracted, output_dir, "ANDROID_LIVE", scan_id, full_tools=True)


def run_offline() -> int:
    raw = input("Archive path: ").strip().strip('"')
    archive = Path(raw).expanduser()
    if not archive.is_file():
        _log("ERROR", f"Archive not found: {archive}")
        return 2
    scan_id = f"CLI_OFFLINE_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}"
    info = ingest_archive(archive, case_id=scan_id, on_progress=_progress)
    extracted = info["results"]
    output_dir = Path(info["extract_dir"])
    return _run_analysis(extracted, output_dir, "OFFLINE_ARCHIVE", scan_id)


def main() -> int:
    print("\nUniversal Forensic Scanner v7.0 CLI\n")
    print("1. Android Live (ADB)")
    print("2. Offline archive")
    print("3. Exit")
    try:
        choice = input("Select mode [1-3]: ").strip()
    except EOFError:
        _log("ERROR", "No menu choice provided")
        return 2
    try:
        if choice == "1":
            return run_live()
        if choice == "2":
            return run_offline()
        if choice == "3":
            return 0
        _log("ERROR", "Invalid choice. Select 1, 2, or 3.")
        return 2
    except KeyboardInterrupt:
        _log("WARN", "Scan cancelled by user")
        return 130
    except Exception as exc:
        _log("ERROR", f"Scan failed: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
