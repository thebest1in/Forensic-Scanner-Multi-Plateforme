"""Live test: full scan on connected POCO device."""
import time
from extractor import run_extraction
from analyzer import analyze, save_report
from remediation_engine import analyze_remediation
from pathlib import Path

SERIAL = "BISG5XZL9LSWZXO7"
OUTPUT = Path("dump_forensic_1784743478")

print("=" * 60)
print("UNIVERSAL FORENSIC SCANNER v7.0 - LIVE TEST")
print("=" * 60)

# Step 1: Extract
print("\n[1/5] EXTRACTING ARTIFACTS...")
extracted = run_extraction(
    serial=SERIAL,
    profile="triage",
    on_progress=lambda p, m: print(f"  [{p:5.1f}%] {m}"),
)
print(f"  -> {len(extracted)} artifacts extracted")

# Step 2: Analyze with ALL tools
print("\n[2/5] RUNNING ANALYSIS (all tools)...")
start = time.time()
result = analyze(
    extracted_files=extracted,
    device_serial=SERIAL,
    dump_dir=OUTPUT,
    on_progress=lambda p, m: print(f"  [{p:5.1f}%] {m}"),
    run_mvt=True,
    run_aleapp=True,
    run_capa=True,
    run_apkid=True,
    run_quark=True,
    run_intel=True,
    run_entropy=True,
    run_browser=True,
    run_mobsf=True,
    run_openmf=True,
    run_osint=True,
    run_correlation=True,
)
elapsed = time.time() - start

# Step 3: Results
print("\n[3/5] ANALYSIS RESULTS")
print(f"  Verdict: {result.verdict}")
print(f"  Risk Score: {result.composite_risk_score}/100 ({result.composite_risk_level})")
print(f"  YARA Matches: {len(result.matched_rules)}")
print(f"  Scanned Files: {result.scanned_files}")
print(f"  Time: {elapsed:.1f}s")

# Tool status
print("\n  TOOL STATUS:")
for tool, status in sorted(result.tool_status.items()):
    icon = {"ok": "OK", "unavailable": "OFF", "disabled": "OFF", "error": "ERR"}.get(status, status)
    print(f"    {tool:15s} [{icon}]")

# New tool results
if result.mobsf_results:
    m = result.mobsf_results[0]
    score = m.get("appsec_score", 0)
    risk = m.get("highest_risk", "?")
    dperms = len(m.get("dangerous_permissions", []))
    secrets = len(m.get("secrets", []))
    print(f"\n  MOBSF: AppSec={score:.0f}/100 Risk={risk}")
    print(f"    Dangerous perms: {dperms}")
    print(f"    Secrets: {secrets}")
    if m.get("spyware_detected"):
        print(f"    SPYWARE: {m['spyware_detected']}")

if result.osint_results:
    o = result.osint_results[0]
    imei = o.get("imei", "")[:8]
    sim_op = o.get("sim_operator", "")
    sim_ctry = o.get("sim_country", "")
    print(f"\n  OSINT: IMEI={imei}... SIM={sim_op} ({sim_ctry})")
    for cat, urls in o.get("lookup_urls", {}).items():
        for u in urls[:2]:
            print(f"    -> {u['name']}: {u['url'][:70]}")

if result.openmf_results:
    om = result.openmf_results[0]
    sev = om.get("severity", "?")
    root = om.get("has_root", False)
    total = om.get("total_extracted", 0)
    dbs = len(om.get("extracted_dbs", []))
    print(f"\n  OPENMF: Status={sev} Root={root} Records={total} DBs={dbs}")

# Step 4: Remediation
print("\n[4/5] REMEDIATION ANALYSIS...")
remed = analyze_remediation(result)
print(f"  Actions taken: {len(remed.actions)}")
print(f"  Actions recommended: {len([a for a in remed.actions if a['action'] == 'UPDATE'])}")

# Step 5: Save report
print("\n[5/5] SAVING REPORT...")
report_path = save_report(result, OUTPUT)
print(f"  Report: {report_path}")

print("\n" + "=" * 60)
print("TEST COMPLETE")
print("=" * 60)
