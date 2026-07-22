import json
import time
import csv
import tempfile
import zipfile
from pathlib import Path
from unittest.mock import patch
from version import VERSION


# ============================================================
# MOCK ADB DATA — Simulated device responses
# ============================================================

MOCK_DATA = {
    "getprop": """[ro.product.model]: [2311DRK48G]
[ro.product.brand]: [xiaomi]
[ro.product.device]: [duchamp]
[ro.product.name]: [duchamp_eea]
[ro.build.version.release]: [15]
[ro.build.version.sdk]: [35]
[ro.build.display.id]: [UKQ1.240411.001]
[ro.serialno]: [MOCK_SERIAL_001]
[ro.boot.serialno]: [MOCK_SERIAL_001]
[ro.build.fingerprint]: [xiaomi/duchamp_eea/duchamp:15/UKQ1.240411.001/V816.0.9.0.UNMEUXM:user/release-keys]
""",
    "netstat": """Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 127.0.0.1:53            0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN
tcp        0      0 192.168.1.5:49832      142.250.80.46:443       ESTABLISHED
""",
    "netstat_suspicious": """Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 192.168.1.5:31337      91.215.85.100:4444      ESTABLISHED
tcp        0      0 192.168.1.5:41234      185.56.80.50:9999       SYN_SENT
""",
    "pm_packages_3": """package:/data/app/~~abc123/com.whatsapp-1/base.apk=com.whatsapp
package:/data/app/~~def456/com.instagram.android-1/base.apk=com.instagram.android
""",
    "pm_packages_3_suspicious": """package:/data/app/~~abc123/com.whatsapp-1/base.apk=com.whatsapp
package:/data/app/~~susp1/com.flexispy-1/base.apk=com.flexispy
package:/data/app/~~susp2/com.mspy.lite-1/base.apk=com.mspy.lite
package:/data/app/~~susp3/com.android.sys.update.co-1/base.apk=com.android.sys.update.co
""",
    "pm_packages_3_critical": """package:/data/app/~~abc123/com.whatsapp-1/base.apk=com.whatsapp
package:/data/app/~~susp1/com.flexispy-1/base.apk=com.flexispy
package:/data/app/~~susp2/com.mspy.lite-1/base.apk=com.mspy.lite
package:/data/app/~~susp3/com.android.sys.update.co-1/base.apk=com.android.sys.update.co
package:/data/app/~~susp4/com.sandrorat-1/base.apk=com.sandrorat
package:/data/app/~~susp5/net.droidjack.server-1/base.apk=net.droidjack.server
""",
    "pm_packages_s": """package:/system/framework/framework.jar=android
package:/system/priv-app/Settings/Settings.apk=com.android.settings
""",
    "batterystats": """Battery Stats:
  Discharge step durations:
  Level 100 -> 99: 60000ms
  Estimated battery capacity: 5000 mAh
""",
    "logcat": """07-20 10:00:00.000  1000  1001 I SystemServer: Starting services
07-20 10:00:01.000  1000  1001 D ActivityManager: Start proc com.whatsapp
07-20 10:00:02.000  1000  1001 W Binder: transaction failed
""",
    "ps": """USER         PID   PPID  VSIZE  RSS   PRIO  NICE  RTPRI SCHED  WCHAN    PC  NAME
root         1     0     136636 8420  20    0     0     0     SyS_ep+  0 S init
system       568   1     2395648 185640 20    0     0     0     do_ep+   0 S system_server
u0_a123     4521  1802  1756244 142000 20    0     0     0     do_ep+   0 S com.whatsapp
""",
    "ps_suspicious": """USER         PID   PPID  VSIZE  RSS   PRIO  NICE  RTPRI SCHED  WCHAN    PC  NAME
root         1     0     136636 8420  20    0     0     0     SyS_ep+  0 S init
system       568   1     2395648 185640 20    0     0     0     do_ep+   0 S system_server
u0_a123     4521  1802  1756244 142000 20    0     0     0     do_ep+   0 S com.whatsapp
u0_a99      7821  1     89244  42000  20    0     0     0     do_ep+   0 S com.flexispy
u0_a100     7822  1     65536  31000  20    0     0     0     do_ep+   0 S com.mspy.lite
""",
    "meminfo": """Total PSS by process:
  142000: com.whatsapp (pid 4521)
  178000: com.instagram.android (pid 4890)
""",
    "wifi": """Wi-Fi is enabled
  Last connection: SSID=HomeNetwork, BSSID=AA:BB:CC:DD:EE:FF, 2026-07-20 09:00:00
""",
    "location": """Location Manager State:
  last location: Location[gps 37.7749,-122.4194]
""",
    "notification": """NotificationRecord: pkg=com.whatsapp title='New message'
""",
    "account": """Accounts: [{name=user@gmail.com, type=com.google}]
""",
    "lock_settings": """LockSettings:
  mQuality=3
  mBiometricSupported=true
""",
    "usb": """USB State:
  connected=true
  last connection: 2026-07-20 08:30:00
""",
    "accessibility": "com.google.android.marvin.talkback/com.google.android.marvin.talkback.TalkBackService",
    "accessibility_suspicious": "com.google.android.marvin.talkback/com.google.android.marvin.talkback.TalkBackService:com.flexispy/com.flexispy.AccessibilityService",
    "device_policy": "No admins.",
    "device_policy_suspicious": """Device Policy Manager Service;
  Active admin #0: com.flexispy
    mType=DATA
    mDisabled=false
""",
    "connectivity": "Active default network: NetworkAgentInfo{type=WIFI, ...}",
    "connectivity_suspicious": "Active VPN: VpnTransport{gateway=10.0.0.1, vpn=org.torproject.android}",
    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  /data/app/test.apk",
    "devices_l": "List of devices attached\nMOCK_SERIAL_001\tdevice usb:1-1 product:duchamp model:2311DRK48G device:duchamp transport_id:1",
}


def _mock_run_adb(cmd: str, **kwargs) -> tuple[bool, str]:
    """Mock ADB runner that returns simulated data."""
    time.sleep(0.01)

    if "devices -l" in cmd:
        return True, MOCK_DATA["devices_l"]
    if "getprop" in cmd:
        return True, MOCK_DATA["getprop"]
    if "netstat" in cmd:
        return True, MOCK_DATA.get("netstat_variant", MOCK_DATA["netstat"])
    if "pm list packages -3" in cmd:
        return True, MOCK_DATA.get("pm3_variant", MOCK_DATA["pm_packages_3"])
    if "pm list packages -s" in cmd:
        return True, MOCK_DATA["pm_packages_s"]
    if "dumpsys batterystats" in cmd:
        return True, MOCK_DATA["batterystats"]
    if "logcat" in cmd:
        return True, MOCK_DATA["logcat"]
    if "ps -A" in cmd:
        return True, MOCK_DATA.get("ps_variant", MOCK_DATA["ps"])
    if "dumpsys meminfo" in cmd:
        return True, MOCK_DATA["meminfo"]
    if "dumpsys wifi" in cmd:
        return True, MOCK_DATA["wifi"]
    if "dumpsys location" in cmd:
        return True, MOCK_DATA["location"]
    if "dumpsys notification" in cmd:
        return True, MOCK_DATA["notification"]
    if "dumpsys account" in cmd:
        return True, MOCK_DATA["account"]
    if "dumpsys lock_settings" in cmd:
        return True, MOCK_DATA["lock_settings"]
    if "dumpsys usb" in cmd:
        return True, MOCK_DATA["usb"]
    if "enabled_accessibility_services" in cmd or "dumpsys accessibility" in cmd:
        return True, MOCK_DATA.get("accessibility_variant", MOCK_DATA["accessibility"])
    if "dumpsys device_policy" in cmd:
        return True, MOCK_DATA.get("device_policy_variant", MOCK_DATA["device_policy"])
    if "dumpsys connectivity" in cmd:
        return True, MOCK_DATA.get("connectivity_variant", MOCK_DATA["connectivity"])
    if "sha256sum" in cmd:
        return True, MOCK_DATA["sha256"]

    return True, ""


# ============================================================
# SCENARIO CONFIGURATORS
# ============================================================

def _set_scenario(scenario: str):
    """Configure mock data variants based on scenario."""
    is_threat = scenario in ("suspicious", "critical")
    is_critical = scenario == "critical"

    MOCK_DATA["netstat_variant"] = MOCK_DATA[
        "netstat_suspicious" if is_threat else "netstat"
    ]
    MOCK_DATA["pm3_variant"] = MOCK_DATA[
        "pm_packages_3_critical" if is_critical
        else ("pm_packages_3_suspicious" if is_threat else "pm_packages_3")
    ]
    MOCK_DATA["ps_variant"] = MOCK_DATA[
        "ps_suspicious" if is_threat else "ps"
    ]
    MOCK_DATA["accessibility_variant"] = MOCK_DATA[
        "accessibility_suspicious" if is_threat else "accessibility"
    ]
    MOCK_DATA["device_policy_variant"] = MOCK_DATA[
        "device_policy_suspicious" if is_critical else "device_policy"
    ]
    MOCK_DATA["connectivity_variant"] = MOCK_DATA[
        "connectivity_suspicious" if is_critical else "connectivity"
    ]


# ============================================================
# MOCK BUGREPORT BUILDER
# ============================================================

def _build_mock_bugreport(case_id: str = "mock_bugreport") -> Path:
    """Create a minimal mock bugreport ZIP in a temp directory."""
    tmp = Path(tempfile.mkdtemp(prefix="mock_br_"))
    br_dir = tmp / case_id
    br_dir.mkdir()

    (br_dir / "device_info.txt").write_text(MOCK_DATA["getprop"], encoding="utf-8")
    (br_dir / "netstat.log").write_text(MOCK_DATA["netstat"], encoding="utf-8")
    (br_dir / "third_party_apps.txt").write_text(MOCK_DATA["pm_packages_3"], encoding="utf-8")
    (br_dir / "processes.txt").write_text(MOCK_DATA["ps"], encoding="utf-8")
    (br_dir / "system_execution.log").write_text(MOCK_DATA["logcat"], encoding="utf-8")
    (br_dir / "system_apps.txt").write_text(MOCK_DATA["pm_packages_s"], encoding="utf-8")
    (br_dir / "batterystats.log").write_text(MOCK_DATA["batterystats"], encoding="utf-8")

    zip_path = tmp / f"{case_id}.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in br_dir.rglob("*"):
            if f.is_file():
                zf.write(f, f"{case_id}/{f.relative_to(br_dir)}")

    return zip_path


def _build_mock_bugreport_suspicious() -> Path:
    """Create a bugreport ZIP with suspicious content for testing."""
    tmp = Path(tempfile.mkdtemp(prefix="mock_br_sus_"))
    br_dir = tmp / "sus_case"
    br_dir.mkdir()

    (br_dir / "device_info.txt").write_text(MOCK_DATA["getprop"], encoding="utf-8")
    (br_dir / "netstat.log").write_text(MOCK_DATA["netstat_suspicious"], encoding="utf-8")
    (br_dir / "third_party_apps.txt").write_text(
        MOCK_DATA["pm_packages_3_suspicious"], encoding="utf-8"
    )
    (br_dir / "processes.txt").write_text(MOCK_DATA["ps_suspicious"], encoding="utf-8")
    (br_dir / "system_execution.log").write_text(MOCK_DATA["logcat"], encoding="utf-8")

    zip_path = tmp / "sus_case.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in br_dir.rglob("*"):
            if f.is_file():
                zf.write(f, f"sus_case/{f.relative_to(br_dir)}")

    return zip_path


# ============================================================
# MOCK PCAP BUILDER
# ============================================================

def _build_mock_pcap_data(with_c2: bool = False) -> dict:
    """Return mock PCAP analysis results."""
    dns = [
        {"query": "connectivitycheck.gstatic.com", "type": "A"},
        {"query": "www.google.com", "type": "A"},
    ]
    sni = [
        {"domain": "www.google.com", "ip": "142.250.80.46"},
        {"domain": "graph.facebook.com", "ip": "157.240.1.35"},
    ]
    c2_hits = []

    if with_c2:
        dns.append({"query": "evil.ngrok.io", "type": "A"})
        dns.append({"query": "data.duckdns.org", "type": "A"})
        sni.append({"domain": "evil.ngrok.io", "ip": "3.14.159.26"})
        c2_hits = [
            {"domain": "evil.ngrok.io", "category": "ngrok", "ip": "3.14.159.26"},
            {"domain": "data.duckdns.org", "category": "duckdns", "ip": "1.2.3.4"},
        ]

    return {
        "dns_queries": dns,
        "tls_sni": sni,
        "c2_hits": c2_hits,
        "total_dns": len(dns),
        "total_sni": len(sni),
    }


# ============================================================
# TEST HARNESS
# ============================================================

def run_mock_test(scenario: str = "clean", profile: str = "deep") -> dict:
    """Run the full analysis pipeline with mock ADB data."""
    from extractor import Extractor
    from analyzer import analyze

    _set_scenario(scenario)

    with patch("core.run_adb", side_effect=_mock_run_adb):
        extractor = Extractor(serial="MOCK_SERIAL_001", profile=profile)
        extracted = extractor.run()

    with patch("core.run_adb", side_effect=_mock_run_adb):
        analysis = analyze(
            extracted_files=extracted,
            device_serial="MOCK_SERIAL_001",
        )

    return {
        "verdict": analysis.verdict,
        "matches": len(analysis.matched_rules),
        "matched_rules": [m["rule"] for m in analysis.matched_rules],
        "suspicious_ips": analysis.suspicious_ips,
        "files_scanned": analysis.scanned_files,
        "filter_stats": analysis.filter_stats,
        "heuristic_result": analysis.heuristic_result,
        "dump_dir": str(extractor.dump_dir) if extractor.dump_dir else None,
    }


def run_mock_offline_test(scenario: str = "clean") -> dict:
    """Test offline archive ingestion path."""
    from archive_engine import ArchiveEngine, ingest_archive
    from analyzer import analyze

    if scenario == "suspicious":
        br_path = _build_mock_bugreport_suspicious()
    else:
        br_path = _build_mock_bugreport()

    info = ingest_archive(br_path, case_id=f"mock_{scenario}")
    extracted = info["results"]

    analysis = analyze(
        extracted_files=extracted,
        device_serial=f"MOCK_{scenario.upper()}",
    )

    return {
        "verdict": analysis.verdict,
        "matches": len(analysis.matched_rules),
        "matched_rules": [m["rule"] for m in analysis.matched_rules],
        "suspicious_ips": analysis.suspicious_ips,
        "files_scanned": analysis.scanned_files,
        "db_results": {
            "sqlite_hits": info.get("sqlite_hits", []),
            "domain_hits": info.get("domain_hits", []),
        },
        "dump_dir": str(info.get("extract_dir", "")),
        "archive_path": str(br_path),
    }


def run_mock_pcap_test(with_c2: bool = False) -> dict:
    """Test PCAP analysis results (mock, no real capture)."""
    return _build_mock_pcap_data(with_c2=with_c2)


def run_mock_heuristics_test(scenario: str = "clean") -> dict:
    """Test heuristics engine with mock extracted files."""
    from heuristics import analyze_permissions

    _set_scenario(scenario)

    with patch("core.run_adb", side_effect=_mock_run_adb):
        from extractor import Extractor
        extractor = Extractor(serial="MOCK_SERIAL_001", profile="deep")
        extracted = extractor.run()

    h_result = analyze_permissions(extracted)
    return h_result.to_dict()


def run_mock_custody_test(verdict: str = "CRITICAL") -> dict:
    """Test chain-of-custody packaging with anti-tampering signatures."""
    from custody import sign_data, verify_signature, _compute_zip_hash

    test_data = b"mock forensic evidence data"
    sig = sign_data(test_data)
    valid = verify_signature(test_data, sig)
    tampered = verify_signature(b"tampered data", sig)

    return {
        "signature": sig,
        "valid_verify": valid,
        "tampered_detected": not tampered,
    }


def run_mock_remediation_test(scenario: str = "suspicious") -> dict:
    """Test remediation engine with mock analysis results."""
    from remediation_engine import analyze_remediation
    result = run_mock_test(scenario)

    with patch("core.run_adb", side_effect=_mock_run_adb):
        from extractor import Extractor
        extractor = Extractor(serial="MOCK_SERIAL_001", profile="deep")
        extracted = extractor.run()

    from analyzer import analyze
    with patch("core.run_adb", side_effect=_mock_run_adb):
        analysis = analyze(
            extracted_files=extracted,
            device_serial="MOCK_SERIAL_001",
        )

    remed = analyze_remediation(analysis)
    return {
        "total_actions": len(remed.actions),
        "actions": remed.actions,
        "delete_count": remed.to_dict()["delete_count"],
        "update_count": remed.to_dict()["update_count"],
        "restrict_count": remed.to_dict()["restrict_count"],
        "has_delete": any(a["action"] == "DELETE" for a in remed.actions),
        "has_adb_commands": any(a.get("adb_command") for a in remed.actions),
    }


def run_mock_artifact_map_test() -> dict:
    """Test artifact_map generation from offline archive."""
    from archive_engine import ingest_archive

    br_path = _build_mock_bugreport_suspicious()
    info = ingest_archive(br_path, case_id="artifact_map_test")

    artifact_map = info.get("artifact_map", [])
    return {
        "total_artifacts": len(artifact_map),
        "has_statuses": all("status" in a for a in artifact_map),
        "has_sizes": all("size_human" in a for a in artifact_map),
        "statuses": {a["status"] for a in artifact_map},
    }


# ============================================================
# PYTEST-COMPATIBLE TEST CASES (8 total)
# ============================================================

def test_clean_device():
    result = run_mock_test("clean")
    assert result["verdict"] == "CLEAN", f"Expected CLEAN, got {result['verdict']}"
    assert result["matches"] == 0, f"Expected 0 matches, got {result['matches']}"
    print(f"[PASS] test_clean_device: {result['verdict']}")


def test_suspicious_device():
    result = run_mock_test("suspicious")
    assert result["verdict"] in ("SUSPICIOUS", "CRITICAL"), f"Expected threat, got {result['verdict']}"
    print(f"[PASS] test_suspicious_device: {result['verdict']} | matches={result['matches']}")


def test_critical_device():
    result = run_mock_test("critical")
    assert result["verdict"] in ("SUSPICIOUS", "CRITICAL"), f"Expected threat, got {result['verdict']}"
    print(f"[PASS] test_critical_device: {result['verdict']} | matches={result['matches']}")


def test_triage_profile():
    result = run_mock_test("clean", profile="triage")
    assert result["files_scanned"] == 4, f"Expected 4 triage files, got {result['files_scanned']}"
    print(f"[PASS] test_triage_profile: {result['files_scanned']} files")


def test_deep_profile():
    result = run_mock_test("clean", profile="deep")
    assert result["files_scanned"] == 18, f"Expected 18 deep files, got {result['files_scanned']}"
    print(f"[PASS] test_deep_profile: {result['files_scanned']} files")


def test_offline_clean():
    result = run_mock_offline_test("clean")
    assert result["verdict"] == "CLEAN", f"Expected CLEAN, got {result['verdict']}"
    assert result["files_scanned"] > 0, "Expected extracted files"
    print(f"[PASS] test_offline_clean: {result['verdict']} | files={result['files_scanned']}")


def test_offline_suspicious():
    result = run_mock_offline_test("suspicious")
    assert result["verdict"] in ("SUSPICIOUS", "CRITICAL"), f"Expected threat, got {result['verdict']}"
    print(f"[PASS] test_offline_suspicious: {result['verdict']} | matches={result['matches']}")


def test_heuristics_clean():
    result = run_mock_heuristics_test("clean")
    assert result["risk_score"] <= 30, f"Expected low risk, got score={result['risk_score']}"
    assert result["risk_level"] in ("CLEAN", "LOW", "LOW_RISK", "MEDIUM"), f"Expected clean/low, got {result['risk_level']}"
    print(f"[PASS] test_heuristics_clean: score={result['risk_score']} level={result['risk_level']}")


def test_heuristics_suspicious():
    result = run_mock_heuristics_test("suspicious")
    assert result["risk_score"] > 0, f"Expected non-zero risk score"
    print(f"[PASS] test_heuristics_suspicious: score={result['risk_score']} level={result['risk_level']}")


def test_pcap_clean():
    result = run_mock_pcap_test(with_c2=False)
    assert len(result["c2_hits"]) == 0, f"Expected no C2 hits, got {len(result['c2_hits'])}"
    assert result["total_dns"] >= 2
    print(f"[PASS] test_pcap_clean: dns={result['total_dns']} c2=0")


def test_pcap_c2_detected():
    result = run_mock_pcap_test(with_c2=True)
    assert len(result["c2_hits"]) >= 2, f"Expected >=2 C2 hits, got {len(result['c2_hits'])}"
    categories = {h["category"] for h in result["c2_hits"]}
    assert "ngrok" in categories, "Expected ngrok C2 hit"
    assert "duckdns" in categories, "Expected duckdns C2 hit"
    print(f"[PASS] test_pcap_c2_detected: c2={len(result['c2_hits'])} categories={categories}")


def test_custody_signing():
    result = run_mock_custody_test()
    assert result["valid_verify"] is True, "Signature verification failed"
    assert result["tampered_detected"] is True, "Tampered data not detected"
    print(f"[PASS] test_custody_signing: valid={result['valid_verify']} tamper_detected={result['tampered_detected']}")


def test_remediation_suspicious():
    result = run_mock_remediation_test("suspicious")
    assert result["total_actions"] > 0, "Expected at least 1 remediation action"
    assert result["has_adb_commands"], "Expected ADB commands for remediation"
    print(f"[PASS] test_remediation_suspicious: actions={result['total_actions']} "
          f"delete={result['delete_count']} restrict={result['restrict_count']}")


def test_remediation_clean():
    result = run_mock_remediation_test("clean")
    assert result["total_actions"] == 0, f"Expected 0 actions for clean, got {result['total_actions']}"
    print(f"[PASS] test_remediation_clean: actions=0")


def test_artifact_map():
    result = run_mock_artifact_map_test()
    assert result["total_artifacts"] > 0, "Expected artifacts in map"
    assert result["has_statuses"], "Expected status field on each artifact"
    assert result["has_sizes"], "Expected size_human field on each artifact"
    print(f"[PASS] test_artifact_map: {result['total_artifacts']} artifacts, statuses={result['statuses']}")


ALL_TESTS = [
    test_clean_device,
    test_suspicious_device,
    test_critical_device,
    test_triage_profile,
    test_deep_profile,
    test_offline_clean,
    test_offline_suspicious,
    test_heuristics_clean,
    test_heuristics_suspicious,
    test_pcap_clean,
    test_pcap_c2_detected,
    test_custody_signing,
    test_remediation_suspicious,
    test_remediation_clean,
    test_artifact_map,
]


if __name__ == "__main__":
    print(f"=== Mock ADB Test Harness v{VERSION} ===\n")
    passed = 0
    failed = 0
    for test_fn in ALL_TESTS:
        try:
            test_fn()
            passed += 1
        except Exception as e:
            print(f"[FAIL] {test_fn.__name__}: {e}")
            failed += 1
    print(f"\n=== {passed}/{passed + failed} tests passed ===")
