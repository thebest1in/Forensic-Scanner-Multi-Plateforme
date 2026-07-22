"""Full offline scan of bugreport-poco.zip with all tools enabled.

Usage:
    python scan_offline.py              # full scan
    python scan_offline.py --quick      # YARA + heuristics only
"""
import sys
import time
import json
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent))

from archive_engine import ingest_archive
from analyzer import analyze, save_report
from core import logger

LOG_DIR = Path(__file__).parent / "logs"
LOG_DIR.mkdir(exist_ok=True)

logger.set_callback(lambda level, msg: print(f"[{level.upper()}] {msg}"))

quick_mode = "--quick" in sys.argv
br_path = Path(__file__).parent / "bugreport-poco.zip"
case_id = f"SCAN_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

print("=" * 70)
print("  FORENSIC OFFLINE SCAN — bugreport-poco.zip")
print("  Poco X6 Pro 5G (duchamp_eea) — 3781 files")
print(f"  Mode: {'QUICK (YARA only)' if quick_mode else 'FULL (all tools)'}")
print("=" * 70)
print()

log_lines = []

def log(msg):
    print(msg, flush=True)
    log_lines.append(msg)

t0 = time.time()

# Phase 1: Ingestion
log("[1/4] Ingesting bugreport ZIP...")
info = ingest_archive(br_path, case_id=case_id)
extracted = info["results"]
extract_dir = info.get("extract_dir")
artifact_map = info.get("artifact_map", [])

log("  Extracted: %d text/log/DB files" % len(extracted))
log("  Artifact map: %d total files indexed" % len(artifact_map))
log("  SQLite hits: %d" % len(info.get("sqlite_hits", [])))
log("  Domain hits: %d" % len(info.get("domain_hits", [])))
log("  Extract dir: %s" % extract_dir)
log("")

# Phase 2: Analysis
log("[2/4] Running analysis...")
result = analyze(
    extracted_files=extracted,
    device_serial=case_id,
    dump_dir=extract_dir,
    on_progress=lambda pct, msg: log("  [%.0f%%] %s" % (pct, msg)),
    run_mvt=False,
    run_aleapp=not quick_mode,
    run_capa=False,
    run_apkid=False,
    run_quark=False,
    run_intel=not quick_mode,
    run_entropy=not quick_mode,
    run_browser=not quick_mode,
    run_correlation=not quick_mode,
)

# Phase 3: Report
log("")
log("[3/4] Generating report...")
report_dir = extract_dir or br_path.parent
report_path = save_report(result, report_dir)

# Also save to logs/
log_file = LOG_DIR / ("scan_%s.log" % case_id)
log_file.write_text("\n".join(log_lines), encoding="utf-8")

json_file = LOG_DIR / ("scan_%s.json" % case_id)
json_report = {
    "case_id": case_id,
    "timestamp": result.timestamp,
    "verdict": result.verdict,
    "composite_risk_score": result.composite_risk_score,
    "composite_risk_level": result.composite_risk_level,
    "yara_matches": result.matched_rules,
    "suspicious_ips": sorted(set(result.suspicious_ips)),
    "aleapp_results": result.aleapp_results,
    "entropy_results": result.entropy_results,
    "browser_results": result.browser_results,
    "correlation_result": result.correlation_result,
    "tool_status": result.tool_status,
    "heuristic_result": result.heuristic_result,
    "filter_stats": result.filter_stats,
    "scanned_files": result.scanned_files,
    "indexed_files": result.indexed_files,
}
json_file.write_text(json.dumps(json_report, indent=2, default=str), encoding="utf-8")

elapsed = time.time() - t0

# Phase 4: Summary
log("")
log("[4/4] Summary")
log("=" * 70)
log("  VERDICT:            %s" % result.verdict)
log("  Composite score:    %d/100 (%s)" % (result.composite_risk_score, result.composite_risk_level))
log("  YARA matches:       %d" % len(result.matched_rules))
log("  Suspicious IPs:     %d" % len(result.suspicious_ips))
log("  ALEAPP findings:    %d" % len(result.aleapp_results))
log("  Entropy flagged:    %d" % len(result.entropy_results))
log("  Browser results:    %d" % len(result.browser_results))
log("  Correlations:       %d" % (result.correlation_result.get("total_correlations", 0) if result.correlation_result else 0))
log("  Files scanned:      %d" % result.scanned_files)

ts = result.tool_status
ok_tools = [k for k, v in ts.items() if v == "ok"]
disabled = [k for k, v in ts.items() if v == "disabled"]
skipped = [k for k, v in ts.items() if v.startswith("skipped")]
unavailable = [k for k, v in ts.items() if v == "unavailable"]
failed = [k for k, v in ts.items() if v == "error"]
log("  Tools OK:           %s" % ", ".join(ok_tools))
if disabled:
    log("  Tools disabled:     %s" % ", ".join(disabled))
if skipped:
    log("  Tools skipped/input:%s" % ", ".join(skipped))
if unavailable:
    log("  Tools unavailable:  %s" % ", ".join(unavailable))
if failed:
    log("  Tools failed:       %s" % ", ".join(failed))

log("  Report:             %s" % report_path.name)
log("  Logs:               %s" % log_file.name)
log("  JSON:               %s" % json_file.name)
log("  Time:               %.1fs" % elapsed)
log("=" * 70)

if result.matched_rules:
    log("")
    log("YARA MATCHES:")
    for r in result.matched_rules:
        tags = ", ".join(r.get("tags", []))
        log("  [%s] %s (tags: %s)" % (r.get("rule"), r.get("file"), tags))

if result.aleapp_results:
    log("")
    log("ALEAPP FINDINGS:")
    for a in result.aleapp_results:
        severity = a.get("severity", "unknown")
        findings = a.get("findings", [])
        log("  Severity: %s | %d findings" % (severity, len(findings)))
        for f in findings[:10]:
            log("    [%s] %s: %s" % (f.get("severity"), f.get("type"), f.get("description", "")[:80]))

if result.suspicious_ips:
    log("")
    log("SUSPICIOUS IPs:")
    for ip in sorted(set(result.suspicious_ips)):
        log("  - %s" % ip)

if result.entropy_results:
    log("")
    log("HIGH ENTROPY FILES:")
    for e in result.entropy_results[:10]:
        log("  %s H=%.2f exfil=%s" % (e.get("file_path", "?")[-50:], e.get("overall_entropy", 0), e.get("exfil_risk")))

if result.correlation_result and result.correlation_result.get("total_correlations", 0) > 0:
    corr = result.correlation_result
    log("")
    log("CORRELATION: %d events (CRITICAL: %d, HIGH: %d)" % (
        corr.get("total_correlations", 0), corr.get("critical_count", 0), corr.get("high_count", 0)))
    for ev in corr.get("events", [])[:10]:
        log("  [%s] %s: %s (%s)" % (ev.get("severity"), ev.get("rule_id"), ev.get("package_name"), ", ".join(ev.get("matched_tools", []))))

log("")
log("Done. All logs saved to: %s" % LOG_DIR)
