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


def _write_summary(result, output_dir: Path, mode: str, scan_id: str,
                    started: float, extraction_seconds: float = 0) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    timeline_path = output_dir / "forensic_timeline.csv"
    event_count = 0
    if timeline_path.exists():
        with timeline_path.open(newline="", encoding="utf-8", errors="replace") as stream:
            event_count = max(0, sum(1 for _ in csv.reader(stream)) - 1)
    # Separate authoritative findings from contextual observations
    authoritative = [f for f in result.matched_rules if f.get("authoritative", True)]
    observations = [f for f in result.matched_rules if not f.get("authoritative", True)]
    # Warnings only for real failures (skip optional tools)
    optional_tools = {"aleapp", "mvt", "capa", "apkid", "quark", "intel",
                      "browser", "mobsf", "openmf"}
    warnings = [
        name for name, status in result.tool_status.items()
        if status in {"unavailable", "error", "timed_out"} and name not in optional_tools
    ]
    limitations = ["CLEAN does not prove that the device is malware-free."]
    for name, status in result.tool_status.items():
        if status in {"unavailable", "error", "timed_out"} and name in optional_tools:
            limitations.append(f"{name} unavailable (optional)")
    artifacts = [{"id": key, "path": str(path), "size_bytes": path.stat().st_size}
                 for key, path in getattr(result, "_cli_extracted", {}).items() if path.exists()]
    analysis_seconds = round(time.time() - started - extraction_seconds, 3)
    total_seconds = round(time.time() - started, 3)
    payload = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "application_version": VERSION,
        "scan_id": scan_id,
        "scan_mode": mode,
        "status": "COMPLETED_WITH_WARNINGS" if warnings else "COMPLETED",
        "started_at_utc": datetime.fromtimestamp(started, UTC).isoformat(),
        "completed_at_utc": datetime.now(UTC).isoformat(),
        "timing": {
            "extraction_seconds": round(extraction_seconds, 3),
            "analysis_seconds": analysis_seconds,
            "reporting_seconds": max(0.0, round(total_seconds - extraction_seconds - analysis_seconds, 3)),
            "total_seconds": total_seconds,
        },
        "verdict": result.verdict,
        "risk_score": result.composite_risk_score,
        "risk_level": result.composite_risk_level,
        "summary": {
            "artifact_count": len(artifacts),
            "finding_count": len(authoritative),
            "observation_count": len(observations),
            "authoritative_finding_count": len(authoritative),
            "timeline_event_count": event_count,
        },
        "artifacts": artifacts,
        "findings": authoritative,
        "observations": observations,
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
        "limitations": limitations,
    }
    path = output_dir / "scan_result.json"
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    temporary.replace(path)
    return path


def _run_analysis(
    extracted: dict[str, Path], output_dir: Path, mode: str, scan_id: str,
    full_tools: bool = False, extraction_seconds: float = 0,
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
        run_mobsf=full_tools,
        run_openmf=full_tools,
        run_osint=full_tools,
        run_correlation=True,
    )
    result._cli_extracted = extracted
    remediation = analyze_remediation(result)
    result._remediation = remediation.to_dict()

    # Report generation with fallback — never lose the scan results
    limitations = list(getattr(result, "_limitations", []))
    report = None
    summary = None
    timeline_path = None
    try:
        report = save_report(result, output_dir)
    except Exception as exc:
        _log("ERROR", f"Legacy report failed: {type(exc).__name__}: {exc}")
        limitations.append(f"Legacy report failed: {type(exc).__name__}")
    try:
        timeline_path = build_timeline(extracted, output_dir)
    except Exception as exc:
        _log("ERROR", f"Timeline failed: {type(exc).__name__}: {exc}")
        limitations.append(f"Timeline failed: {type(exc).__name__}")
    try:
        summary = _write_summary(result, output_dir, mode, scan_id, started,
                                  extraction_seconds=extraction_seconds)
    except Exception as exc:
        _log("ERROR", f"Canonical report failed: {type(exc).__name__}: {exc}")
        limitations.append(f"Canonical report failed: {type(exc).__name__}")
        # Emergency: write minimal scan_result.json so results are not lost
        try:
            emergency = {
                "status": "COMPLETED_WITH_REPORTING_ERROR",
                "scan_id": scan_id,
                "scan_mode": mode,
                "verdict": str(result.verdict),
                "risk_score": result.composite_risk_score,
                "risk_level": result.composite_risk_level,
                "forensic_findings": result.forensic_findings,
                "mitre_mappings": result.mitre_mappings,
                "tool_status": result.tool_status,
                "limitations": limitations,
                "error": {"type": type(exc).__name__, "message": str(exc)},
            }
            emergency_path = output_dir / "scan_result_emergency.json"
            emergency_path.write_text(json.dumps(emergency, indent=2, default=str), encoding="utf-8")
            _log("WARN", f"Emergency report saved: {emergency_path}")
            summary = emergency_path
        except Exception:
            _log("ERROR", "Emergency report also failed")

    if summary:
        _log("OK", f"JSON report: {summary}")
    if report:
        _log("OK", f"Legacy report: {report}")
    if timeline_path:
        _log("OK", f"Timeline CSV: {timeline_path}")
    _log("RESULT", f"{result.verdict} — {result.composite_risk_score}/100 ({result.composite_risk_level})")
    _log("INFO", f"Tool health: {result.tool_status}")
    return 0


# ============================================================
# ANDROID MODES
# ============================================================

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
    print("\nProfiles:")
    print("  triage   — 4 artifacts, fast (30s)")
    print("  deep    — 18 artifacts, thorough (2min)")
    print("  forensic — 45 artifacts, full Cellebrite-grade (2min)")
    profile = input("\nProfile [triage/deep/forensic] (default forensic): ").strip().lower() or "forensic"
    if profile not in {"triage", "deep", "forensic"}:
        _log("ERROR", "Invalid profile. Choose triage, deep, or forensic.")
        return 2
    scan_id = f"CLI_LIVE_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}"
    output_dir = ROOT / "output" / scan_id
    _log("INFO", "Acquiring Android artifacts through ADB (read-only commands)...")
    extraction_start = time.time()
    extracted = run_extraction(serial, profile, _progress)
    extraction_seconds = time.time() - extraction_start
    if not extracted:
        _log("ERROR", "No artifacts were acquired")
        return 1
    _log("INFO", "All optional analyzers enabled for this Android Live scan")
    return _run_analysis(extracted, output_dir, "ANDROID_LIVE", scan_id,
                         full_tools=True, extraction_seconds=extraction_seconds)


def run_offline() -> int:
    raw = input("Archive path: ").strip().strip('"')
    # Strip invisible Unicode directional markers (Windows clipboard artifact)
    raw = raw.encode("utf-8").decode("utf-8").strip("\u200e\u200f\u202a\u202b\u202c\u202d\u202e")
    archive = Path(raw).expanduser()
    if not archive.is_file():
        _log("ERROR", f"Archive not found: {archive}")
        return 2
    scan_id = f"CLI_OFFLINE_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}"
    extraction_start = time.time()
    info = ingest_archive(archive, case_id=scan_id, on_progress=_progress)
    extraction_seconds = time.time() - extraction_start
    extracted = info["results"]
    output_dir = Path(info["extract_dir"])
    return _run_analysis(extracted, output_dir, "OFFLINE_ARCHIVE", scan_id,
                         full_tools=True, extraction_seconds=extraction_seconds)


# ============================================================
# iOS MODES
# ============================================================

def _run_ios_live() -> int:
    """Run strictly live iOS acquisition over USB; never create a backup."""
    from adapters.ios_adapter import IOSAdapter

    adapter = IOSAdapter()
    _log("INFO", "Detecting Apple mobile devices (live USB only)...")
    if not adapter.can_handle(""):
        _log("ERROR", "No trusted iOS device available over USB")
        _log("INFO", "Unlock the iPhone and tap 'Trust'. A backup is not used in mode 3.")
        return 1

    device_info = adapter.get_device_info("")
    _log("OK", f"iOS device detected: {device_info.model or 'Apple device'}")
    _log("INFO", f"  iOS: {device_info.android_version or 'unknown'}")

    # Profile selection
    print("\nProfiles:")
    print("  triage   — live device info + installed applications")
    print("  deep     — extended live lockdown/syslog acquisition")
    print("  forensic — maximum live diagnostics (no backup, no password)")
    profile = input("\nProfile [triage/deep/forensic] (default forensic): ").strip().lower() or "forensic"
    if profile not in {"triage", "deep", "forensic"}:
        _log("ERROR", "Invalid profile. Choose triage, deep, or forensic.")
        return 2

    scan_id = f"CLI_IOS_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}"
    output_dir = ROOT / "output" / scan_id

    extraction_start = time.time()
    _log("INFO", "Starting live iOS acquisition (no backup)...")
    extracted = adapter.extract("", profile=profile)
    extraction_seconds = time.time() - extraction_start
    if not extracted:
        _log("ERROR", "Live iOS acquisition returned no artifacts")
        return 1
    _log("OK", f"Live acquisition completed: {len(extracted)} artifacts (no backup)")

    # Run analysis
    return _run_analysis(extracted, output_dir, f"IOS_LIVE_{profile.upper()}", scan_id,
                         full_tools=True,
                         extraction_seconds=extraction_seconds)


def _parse_ios_backup(
    backup_dir: Path,
    profile: str,
    output_dir: Path,
) -> dict[str, Path]:
    """Parse iOS backup data and return artifact paths."""
    output_dir.mkdir(parents=True, exist_ok=True)
    extracted = {}

    def _try_parse(module_name: str, func_name: str, artifact_id: str) -> Path | None:
        """Try to run a parser and save results to a JSON file."""
        try:
            import importlib
            mod = importlib.import_module(module_name)
            func = getattr(mod, func_name)
            result = func(backup_dir)
            if result and isinstance(result, dict):
                out_path = output_dir / f"{artifact_id}.json"
                out_path.write_text(
                    json.dumps(result, indent=2, default=str, ensure_ascii=False),
                    encoding="utf-8",
                )
                return out_path
        except Exception as e:
            _log("WARNING", f"Parser {module_name}.{func_name} failed: {e}")
        return None

    # Triage parsers
    parsers_to_run = [
        ("ios.backup", "read_manifest_database", "backup_manifest"),
        ("ios.backup", "parse_info_plist", "backup_metadata"),
        ("ios.applications", "parse_installed_apps", "installed_applications"),
    ]

    # Deep parsers
    if profile in ("deep", "forensic"):
        parsers_to_run.extend([
            ("ios.parsers.sms", "parse_sms", "sms_messages"),
            ("ios.parsers.calls", "parse_call_history", "call_history"),
            ("ios.parsers.contacts", "parse_contacts", "contacts"),
            ("ios.parsers.safari", "parse_safari_history", "safari_history"),
            ("ios.parsers.safari", "parse_safari_downloads", "safari_downloads"),
            ("ios.parsers.safari", "parse_safari_bookmarks", "safari_bookmarks"),
            ("ios.parsers.wifi", "parse_wifi_networks", "wifi_networks"),
            ("ios.parsers.profiles", "parse_configuration_profiles", "configuration_profiles"),
            ("ios.parsers.application_domains", "parse_application_domains", "application_domains"),
            ("ios.parsers.analytics", "parse_analytics", "analytics_logs"),
            ("ios.parsers.analytics", "parse_crash_reports", "crash_reports"),
            ("ios.parsers.analytics", "parse_data_usage", "data_usage"),
        ])

    # Forensic-only parsers
    if profile == "forensic":
        parsers_to_run.extend([
            ("ios.parsers.profiles", "parse_managed_devices", "managed_devices"),
            ("ios.parsers.profiles", "parse_vpn_configurations", "vpn_configurations"),
        ])

    for module, func, artifact_id in parsers_to_run:
        path = _try_parse(module, func, artifact_id)
        if path:
            extracted[artifact_id] = path

    # Build iOS timeline
    if profile in ("deep", "forensic"):
        try:
            from ios.timeline import build_ios_timeline
            # Collect all parsed JSON data for timeline
            parsed_data = {}
            for key in ["sms_messages", "call_history", "safari_history",
                         "wifi_networks", "installed_applications"]:
                if key in extracted:
                    try:
                        parsed_data[key.split("_")[0] if "_" in key else key] = json.loads(
                            extracted[key].read_text(encoding="utf-8")
                        )
                    except Exception:
                        pass
            timeline_path = build_ios_timeline(backup_dir, parsed_data, output_dir)
            extracted["ios_timeline"] = timeline_path
        except Exception as e:
            _log("WARNING", f"iOS timeline build failed: {e}")

    return extracted


def _run_ios_offline() -> int:
    """Run iOS analysis on an existing backup directory."""
    raw = input("iOS backup directory path: ").strip().strip('"')
    raw = raw.encode("utf-8").decode("utf-8").strip("\u200e\u200f\u202a\u202b\u202c\u202d\u202e")
    backup_dir = Path(raw).expanduser()

    if not backup_dir.is_dir():
        _log("ERROR", f"Backup directory not found: {backup_dir}")
        return 2

    # Verify it's an iOS backup
    manifest = backup_dir / "Manifest.db"
    info_plist = backup_dir / "Info.plist"
    if not manifest.exists() and not info_plist.exists():
        _log("ERROR", "Not a valid iOS backup (Manifest.db and Info.plist not found)")
        return 2

    print("\nProfiles:")
    print("  triage   — device info + installed apps + basic backup analysis")
    print("  deep    — full backup + SMS/calls/contacts/Safari + timeline")
    print("  forensic — encrypted backup + sysdiagnose + IOC correlation + MVT")
    profile = input("\nProfile [triage/deep/forensic] (default forensic): ").strip().lower() or "forensic"
    if profile not in {"triage", "deep", "forensic"}:
        _log("ERROR", "Invalid profile. Choose triage, deep, or forensic.")
        return 2

    scan_id = f"CLI_IOS_OFFLINE_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}"
    output_dir = ROOT / "output" / scan_id

    # Encrypted backups require an interactive password; never persist it.
    if profile == "forensic":
        from ios.encrypted_backup import (
            decrypt_backup,
            is_backup_encrypted,
            prompt_backup_password,
        )
        if is_backup_encrypted(backup_dir):
            password = prompt_backup_password()
            if not password:
                _log("ERROR", "Encrypted backup requires a password; scan cancelled")
                return 1
            decrypted_dir = output_dir / "decrypted_backup"
            if not decrypt_backup(backup_dir, password, decrypted_dir):
                _log("ERROR", "Encrypted backup decryption failed")
                password = None
                return 1
            backup_dir = decrypted_dir
            password = None

    _log("INFO", f"Parsing iOS backup: {backup_dir.name}")
    extraction_start = time.time()
    extracted = _parse_ios_backup(backup_dir, profile, output_dir)
    extraction_seconds = time.time() - extraction_start

    if not extracted:
        _log("ERROR", "No data could be parsed from backup")
        return 1

    _log("OK", f"Parsed {len(extracted)} artifact groups from backup")

    return _run_analysis(extracted, output_dir, f"IOS_OFFLINE_{profile.upper()}", scan_id,
                         full_tools=True,
                         extraction_seconds=extraction_seconds)


# ============================================================
# MAIN MENU
# ============================================================

def main() -> int:
    print(f"\nUniversal Forensic Scanner {VERSION} CLI\n")
    print("1. Android Live (ADB)")
    print("2. Android Offline archive")
    print("3. iOS Live USB (no backup)")
    print("4. iOS Offline backup")
    print("5. Exit")
    try:
        choice = input("Select mode [1-5]: ").strip()
    except EOFError:
        _log("ERROR", "No menu choice provided")
        return 2
    try:
        if choice == "1":
            return run_live()
        if choice == "2":
            return run_offline()
        if choice == "3":
            return _run_ios_live()
        if choice == "4":
            return _run_ios_offline()
        if choice == "5":
            return 0
        _log("ERROR", "Invalid choice. Select 1, 2, 3, 4, or 5.")
        return 2
    except KeyboardInterrupt:
        _log("WARN", "Scan cancelled by user")
        return 130
    except Exception as exc:
        _log("ERROR", f"Scan failed: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
