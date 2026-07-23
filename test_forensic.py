"""Forensic profile test: 45 commands + 14 modules — saves full reports."""
import json
import subprocess
import time
from extractor import run_extraction
from analyzer import analyze, save_report
from remediation_engine import analyze_remediation
from timeline import build_timeline
from pathlib import Path

# Auto-detect device serial
def get_device_serial():
    try:
        r = subprocess.run(["adb", "devices"], capture_output=True, text=True, timeout=10)
        for line in r.stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 2 and parts[1] == "device":
                return parts[0]
    except Exception:
        pass
    return None

SERIAL = get_device_serial()
if not SERIAL:
    print("ERROR: No Android device found")
    exit(1)
print(f"Device: {SERIAL}")

OUTPUT = Path("dump_forensic_rc4")
OUTPUT.mkdir(exist_ok=True)

print("=" * 60)
print("FORENSIC PROFILE SCAN — 45 commands + 6 modules")
print("=" * 60)

# --- EXTRACTION ---
print("\n[1/5] EXTRACTING ARTIFACTS (forensic profile)...")
start_ext = time.time()
extracted = run_extraction(
    serial=SERIAL,
    profile="forensic",
    on_progress=lambda p, m: print(f"  [{p:5.1f}%] {m}"),
)
ext_time = time.time() - start_ext
print(f"  -> {len(extracted)} artifacts extracted in {ext_time:.1f}s")

print("\nEXTRACTED ARTIFACTS:")
for key in sorted(extracted.keys()):
    p = extracted[key]
    size = p.stat().st_size if p.exists() else 0
    print(f"  {key:40s} {size:>10,d} bytes")

# --- ANALYSIS ---
print("\n[2/5] RUNNING ANALYSIS (all tools)...")
start_analysis = time.time()
result = analyze(
    extracted_files=extracted,
    device_serial=SERIAL,
    dump_dir=OUTPUT,
    on_progress=lambda p, m: print(f"  [{p:5.1f}%] {m}"),
    run_mvt=True, run_aleapp=True, run_capa=True,
    run_apkid=True, run_quark=True, run_intel=True,
    run_entropy=True, run_browser=True, run_mobsf=True,
    run_openmf=True, run_osint=True, run_correlation=True,
)
analysis_time = time.time() - start_analysis

# --- REMEDIATION ---
print("\n[3/5] REMEDIATION...")
remed = analyze_remediation(result)
result._remediation = remed.to_dict()
result._cli_extracted = extracted

# --- TIMELINE ---
print("\n[4/5] BUILDING TIMELINE...")
timeline_path = build_timeline(extracted, OUTPUT)

# --- SAVE REPORTS ---
print("\n[5/5] SAVING REPORTS...")
report_path = save_report(result, OUTPUT)

# Write canonical scan_result.json
from cli import _write_summary
canonical = _write_summary(result, OUTPUT, "ANDROID_FORENSIC_LIVE",
                           f"FORENSIC_{int(time.time())}", start_ext,
                           extraction_seconds=ext_time)

print(f"\n  Legacy report:  {report_path}")
print(f"  Canonical JSON: {canonical}")
if timeline_path:
    print(f"  Timeline CSV:   {timeline_path}")

# --- RESULTS SUMMARY ---
print("\n" + "=" * 60)
print("RESULTS SUMMARY")
print("=" * 60)
print(f"  Profile:            forensic")
print(f"  Artifacts:          {len(extracted)}")
print(f"  Scanned files:      {result.scanned_files}")
print(f"  YARA matches:       {len(result.matched_rules)}")
auth = sum(1 for r in result.matched_rules if r.get("authoritative", True))
print(f"    authoritative:    {auth}")
print(f"    contextual:       {len(result.matched_rules) - auth}")
print(f"  Forensic findings:  {len(result.forensic_findings)}")
print(f"  MITRE mappings:     {len(result.mitre_mappings)}")
print(f"  Verdict:            {result.verdict}")
print(f"  Risk score:         {result.composite_risk_score}/100 ({result.composite_risk_level})")
print(f"  Extraction time:    {ext_time:.1f}s")
print(f"  Analysis time:      {analysis_time:.1f}s")
print(f"  Total time:         {time.time() - start_ext:.1f}s")

# --- TOOL STATUS ---
print("\n  TOOL STATUS:")
for tool, status in sorted(result.tool_status.items()):
    labels = {"ok": "OK", "unavailable": "OFF", "disabled": "OFF", "error": "ERR",
              "skipped_no_root": "no_root", "skipped_no_input": "no_input"}
    print(f"    {tool:20s} [{labels.get(status, status)}]")

# --- FORENSIC FINDINGS (top 10) ---
if result.forensic_findings:
    print(f"\n  FORENSIC FINDINGS ({len(result.forensic_findings)} total):")
    for f in result.forensic_findings[:10]:
        ev = f.get("evidence", f.get("package", ""))[:55]
        print(f"    {f['type']:35s} [{f.get('severity', '?'):8s}] {ev}")
    if len(result.forensic_findings) > 10:
        print(f"    ... +{len(result.forensic_findings) - 10} more")

# --- MITRE MAPPINGS ---
if result.mitre_mappings:
    print(f"\n  MITRE ATT&CK ({len(result.mitre_mappings)} mappings):")
    for m in result.mitre_mappings:
        print(f"    {m['technique']:10s} {m['tactic']:22s} {m['name']}")
        if m.get("package"):
            print(f"               Package: {m['package']}")

# --- OSINT ---
if result.osint_results:
    o = result.osint_results[0]
    print(f"\n  OSINT: IMEI={o.get('imei', '?')} SIM={o.get('sim_operator', '?')} ({o.get('sim_country', '?')})")

# --- WARNINGS ---
warnings = [name for name, status in result.tool_status.items()
            if status in {"unavailable", "error", "timed_out"}]
optional = {"aleapp", "mvt", "capa", "apkid", "quark", "intel", "browser", "mobsf", "openmf"}
real_warnings = [w for w in warnings if w not in optional]
optional_unavail = [w for w in warnings if w in optional]
if real_warnings:
    print(f"\n  WARNINGS: {real_warnings}")
if optional_unavail:
    print(f"  OPTIONAL UNAVAILABLE: {optional_unavail}")

print("\n" + "=" * 60)
print("DONE — reports saved to dump_forensic_rc4/")
print("=" * 60)
