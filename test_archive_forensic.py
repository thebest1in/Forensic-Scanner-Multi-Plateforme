"""Scan bugreport-poco.zip with full forensic analysis — no mock data."""
import json
import time
from archive_engine import ingest_archive
from analyzer import analyze, save_report
from remediation_engine import analyze_remediation
from timeline import build_timeline
from pathlib import Path

ARCHIVE = Path(r"C:\Users\imadfdl\Desktop\SECURITY PHONE\bugreport-poco.zip")
OUTPUT = Path("dump_archive_rc4")
OUTPUT.mkdir(exist_ok=True)

print("=" * 60)
print("ARCHIVE SCAN — bugreport-poco.zip (37.9 MB)")
print("=" * 60)

# --- EXTRACTION ---
print("\n[1/5] EXTRACTING ARCHIVE...")
start_ext = time.time()
info = ingest_archive(ARCHIVE, case_id="ARCHIVE_RC4", on_progress=lambda p, m: print(f"  [{p:5.1f}%] {m}"))
ext_time = time.time() - start_ext
extracted = info["results"]
print(f"  -> {len(extracted)} files extracted in {ext_time:.1f}s")

# --- ANALYSIS ---
print("\n[2/5] RUNNING ANALYSIS (all tools)...")
start_analysis = time.time()
result = analyze(
    extracted_files=extracted,
    device_serial="bugreport-poco",
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

from cli import _write_summary
canonical = _write_summary(result, OUTPUT, "ARCHIVE_FORENSIC",
                           f"ARCHIVE_RC4_{int(time.time())}", start_ext,
                           extraction_seconds=ext_time)

print(f"\n  Legacy report:  {report_path}")
print(f"  Canonical JSON: {canonical}")
if timeline_path:
    print(f"  Timeline CSV:   {timeline_path}")

# --- RESULTS ---
print("\n" + "=" * 60)
print("RESULTS SUMMARY")
print("=" * 60)
print(f"  Source:           bugreport-poco.zip (37.9 MB)")
print(f"  Files extracted:  {len(extracted)}")
print(f"  Scanned files:    {result.scanned_files}")
print(f"  YARA matches:     {len(result.matched_rules)}")
auth = sum(1 for r in result.matched_rules if r.get("authoritative", True))
print(f"    authoritative:  {auth}")
print(f"    contextual:     {len(result.matched_rules) - auth}")
print(f"  Forensic findings: {len(result.forensic_findings)}")
print(f"  MITRE mappings:   {len(result.mitre_mappings)}")
print(f"  Verdict:          {result.verdict}")
print(f"  Risk score:       {result.composite_risk_score}/100 ({result.composite_risk_level})")
print(f"  Extraction:       {ext_time:.1f}s")
print(f"  Analysis:         {analysis_time:.1f}s")
print(f"  Total:            {time.time() - start_ext:.1f}s")

print("\n  TOOL STATUS:")
for tool, status in sorted(result.tool_status.items()):
    labels = {"ok": "OK", "unavailable": "OFF", "disabled": "OFF", "error": "ERR",
              "skipped_no_root": "no_root", "skipped_no_input": "no_input"}
    print(f"    {tool:20s} [{labels.get(status, status)}]")

if result.forensic_findings:
    print(f"\n  FORENSIC FINDINGS ({len(result.forensic_findings)} total):")
    for f in result.forensic_findings[:15]:
        ev = f.get("evidence", f.get("package", ""))[:55]
        print(f"    {f['type']:35s} [{f.get('severity', '?'):8s}] {ev}")
    if len(result.forensic_findings) > 15:
        print(f"    ... +{len(result.forensic_findings) - 15} more")

if result.mitre_mappings:
    print(f"\n  MITRE ATT&CK ({len(result.mitre_mappings)} mappings):")
    for m in result.mitre_mappings:
        print(f"    {m['technique']:10s} {m['tactic']:22s} {m['name']}")

if result.matched_rules:
    print(f"\n  YARA MATCHES ({len(result.matched_rules)}):")
    for r in result.matched_rules[:10]:
        cls = r.get("classification", "?")
        conf = r.get("confidence", 0)
        auth_flag = "AUTH" if r.get("authoritative", True) else "CTX"
        print(f"    {r.get('rule', '?'):30s} [{auth_flag}] {cls} ({conf:.2f})")
        print(f"      File: {r.get('file_path', '?')}")
    if len(result.matched_rules) > 10:
        print(f"    ... +{len(result.matched_rules) - 10} more")

if result.osint_results:
    o = result.osint_results[0]
    print(f"\n  OSINT: IMEI={o.get('imei', '?')} SIM={o.get('sim_operator', '?')} ({o.get('sim_country', '?')})")

print("\n" + "=" * 60)
print("DONE — reports in dump_archive_rc4/")
print("=" * 60)
