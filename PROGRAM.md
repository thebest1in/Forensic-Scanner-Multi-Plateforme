# Universal Forensic Scanner v7.0 — Complete Program Guide

## Project Overview

Cellebrite-grade Android forensic scanner with YARA-based threat detection,
heuristic permission analysis, 11 tool bridges, 6 forensic analysis modules,
and a recommendations engine. Produces JSON reports with composite risk
scoring (0–100) and authoritative verdict classification.

```
Device (ADB) → Extractor (37 artifacts) → Analyzer (YARA + forensics)
  → Tools (MVT, MobSF, OpenMF, OSINT, entropy, correlation...)
  → Composite risk score → Verdict → Report
```

## Quick Start

```bat
run_cli.bat                              # CLI menu
dist\UniversalForensicScanner\UniversalForensicScanner.exe        # GUI
dist\UniversalForensicScanner\UniversalForensicScanner_CLI.exe    # CLI EXE
```

Both EXEs are self-contained with Tcl/Tk bundled. No Python required.

## Verified 2026-07-22

```
Device:       POCO 2311DRK48G, Android 16, serial BISG5XZL9LSWZXO7
Profile:      Triage (4 artifacts) + Forensic analysis modules
YARA:         3 matches — Frida (authorized_forensic_tooling × 2),
              AnyDesk (dual_use_observation × 1)
Forensics:    Port 27042 (Frida) detected by network module
Composite:    0/100 CLEAN
Verdict:      CLEAN — no corroborating malicious evidence
OSINT:        IMEI=86758007****749 (masked), SIM=MAROC TELECOM
OpenMF:       skipped_no_root (device not rooted)
IMEI:         Masked in all JSON output
pytest:       22/22 | mock_adb: 15/15 | Ruff: clean
```

---

## Architecture

### Manifest System (v5.0)

Two manifests exist; the unified loader prefers `android_artifacts.json`:

| Profile | Commands | Purpose |
|---------|----------|---------|
| `triage` | 4 | Fast risk footprint: getprop, netstat, pm list, ps |
| `deep` | 18 | Full dump: battery, logcat, wifi, location, accounts, APK hashes |
| `forensic` | 37 | Cellebrite-grade: all deep + system integrity, partitions, signatures, DNS, hooking, spyware, memory, certs, network, services, overlay, SMS, call log, contacts, WiFi MAC, SIM country |

**Loading path:** `extractor.py` → `android_artifacts.json` → `artifacts.json` (fallback).
The adapter (`adapters/android_adapter.py`) also loads the same manifest with its own fallback.

### Extraction Flow

```
Extractor.run(profile)
  → For each command in manifest:
      → Push script if needed (hash_apks.sh)
      → core.run_adb(cmd) with timeout
      → Write output to dump_dir/{output_file}
  → Return {artifact_id: file_path}
```

### Analyzer Pipeline

```
analyze(extracted_files, ...)
  → Phase 1-6:  YARA scan (4 files, skip junk/binary)
  → Phase 7:    IOC cross-reference (25,954 known malicious IPs)
  → Phase 8:    Forensic artifact processing (6 existing + 6 new modules)
  → Phase 9:    Heuristic permission analysis (132 apps)
  → Phase 10:   Scan delta computation (history comparison)
  → Phase 11:   Concurrent tool dispatch (11 tools, 6 threads)
  → Phase 12:   Cross-tool correlation
  → Composite risk score → Verdict → Summary
```

---

## YARA Classification System

### Forensic Context Allowlist

When `forensic_context=True` (default), YARA matches are classified by context:

| Classification | Condition | Authoritative | Confidence | Risk Weight |
|---------------|-----------|---------------|------------|-------------|
| `authorized_forensic_tooling` | Rule tags match `FORENSIC_TOOL_ALLOWLIST` | False | 0.10 | 0 (contextual) |
| `dual_use_observation` | Package in `KNOWN_DUAL_USE_PACKAGES` or `remote_access`+`rat` tags | False | 0.30 | 0 (contextual) |
| `strong suspicious evidence` | None of the above | True | 0.65–0.95 | Full weighted |

**Allowlisted tools:** Frida, Xposed, Substrate, Magisk (tags: `frida`, `hooking_framework`, `xposed`, `substrate`, `magisk`, `root`)

**Dual-use apps:** AnyDesk, TeamViewer, LogMeIn, Splashtop, RealVNC, Chrome Remote Desktop

### Composite Risk Scoring

| Bucket | Max Points | Source |
|--------|-----------|--------|
| YARA rule matches | 35 | Authoritative rules: full weight; contextual: 25% dampened |
| Heuristic permission score | 25 | Suspicious permission combinations across 132 apps |
| Tool results (MVT/APKiD/Quark/capa/ALEAPP) | 20 | Redistributed proportionally if tools unavailable |
| IOC/network intelligence | 10 | Malicious IP matches, OTX intel |
| Entropy/browser/correlation | 10 | File entropy anomalies, browser artifacts, cross-tool events |

**Thresholds:** ≥70 CRITICAL, ≥40 SUSPICIOUS, >10 LOW_RISK, else CLEAN

**Verdict escalation:** Only authoritative YARA rules with critical tags
(`pegasus`, `zero_click`, `stalkerware`, `spyware`, etc.) can escalate
verdict above the composite risk level.

---

## Forensic Analysis Modules

Six dedicated modules parse already-collected artifacts:

### 1. `system_integrity.py`
Parses `system_properties.txt`. Verifies 7 security properties:
- `ro.debuggable` (expected: 0)
- `ro.secure` (expected: 1)
- `ro.build.type` (expected: user)
- `ro.adb.secure` (expected: 1)
- `ro.boot.secureboot` (expected: 1)
- `ro.secureboot.lockstate` (expected: locked)
- `odsign.verification.success` (expected: 1)

### 2. `partition_verification.py`
Parses `partition_integrity.txt`. Verifies 9 partition digests:
- system, vendor, product, odm, system_ext, vendor_dlkm, odm_dlkm, system_dlkm, mi_ext
- Detects missing, empty, or truncated digests

### 3. `signature_verification.py`
Parses `apk_signature.txt` (`pm verify` output).
- Detects verification failures, unsigned APKs
- Flags dual-use apps (AnyDesk, TeamViewer) as verified observations

### 4. `network_forensics.py`
Parses `netstat.log` and `dns_configuration.txt`.
- Detects suspicious ports: 27042 (Frida), 27043, 4444, 5555, 8080, 9090, 3128, 1080
- Audits DNS servers for custom/hijacked configurations

### 5. `account_analysis.py`
Parses `accounts.txt` (`dumpsys account`).
- Enumerates synced accounts and account types
- Detects cloud sync accounts

### 6. `proxy_vpn_detection.py`
Parses `vpn_proxy_config.txt` (`global.http_proxy`, `global.socks_proxy`).
- Detects HTTP proxy configuration
- Detects SOCKS proxy configuration

---

## Tool Bridges (11 concurrent)

| Tool | Status Field | What It Does |
|------|-------------|--------------|
| **MVT** | `mvt` | IOC check against 16 Amnesty/stalkerware indicator feeds |
| **MobSF** | `mobsf` | APK static analysis via REST API (permissions, secrets, code analysis) |
| **OpenMF** | `openmf` | Device data extraction via collector.py (requires root) |
| **OSINT** | `osint` | Phone/IMEI/SIM extraction, lookup URL generation |
| **APKiD** | `apkid` | Packer/protector detection |
| **Quark** | `quark` | Behavioral malware analysis |
| **Capa** | `capa` | Capability-based static analysis |
| **ALEAPP** | `aleapp` | Android log artifact parsing |
| **VirusTotal** | `vt` | Malicious IP reputation lookup |
| **Intel/OTX** | `intel` | AlienVault OTX threat intelligence |
| **Entropy** | `entropy` | File entropy anomaly detection |
| **Browser** | `browser` | Browser forensics artifact extraction |
| **Correlation** | `correlation` | Cross-tool event correlation |

### Tool Status Values
- `ok` — Tool ran successfully with findings
- `disabled` — Tool was not enabled
- `skipped_no_input` — Tool requires input not available (e.g., no APK for MobSF)
- `skipped_no_root` — Tool requires root access (OpenMF)
- `unavailable` — Tool binary not found
- `error` — Tool execution failed

---

## Recommendations Engine

`recommendations_engine.py` generates prioritized remediation actions:

| Priority | Action | Examples |
|----------|--------|----------|
| `CRITICAL` | `DELETE` | Known spyware packages (Pegasus, FlexiSpy, mSpy) |
| `HIGH` | `UNINSTALL` | Remote access tools (AnyDesk, TeamViewer) |
| `MEDIUM` | `UPDATE` | Outdated apps with known vulnerabilities |
| `LOW` | `RESTRICT` | Apps with excessive permissions |

**High-risk app database:** AnyDesk, Ear Spy, Turbo VPN, V720, and 20+ known stalkerware/RAT packages.

---

## Recommendations Engine

`recommendations_engine.py` generates prioritized remediation actions:

| Priority | Action | Examples |
|----------|--------|----------|
| `CRITICAL` | `DELETE` | Known spyware packages (Pegasus, FlexiSpy, mSpy) |
| `HIGH` | `UNINSTALL` | Remote access tools (AnyDesk, TeamViewer) |
| `MEDIUM` | `UPDATE` | Outdated apps with known vulnerabilities |
| `LOW` | `RESTRICT` | Apps with excessive permissions |

**High-risk app database:** AnyDesk, Ear Spy, Turbo VPN, V720, and 20+ known stalkerware/RAT packages.

---

## ADB Command Categories (37 forensic commands)

### Device Identification (2)
- `getprop` — full device properties
- `getprop ro.product.model && ro.build.version.release && ro.build.display.id && ro.serialno`

### Root Detection (1)
- `getprop ro.debuggable && ro.secure && ro.build.type && ro.adb.secure && ro.boot.secureboot && ro.secureboot.lockstate && ro.secureboot.devicelock && which su && ls /system/bin/su && ls /system/xbin/su && ls /sbin/su`

### Package Analysis (3)
- `pm list packages -3 -f` — third-party apps
- `pm list packages -s -f` — system apps
- `pm list packages | grep -E` — known spyware scan

### Permission Analysis (1)
- `settings get secure enabled_accessibility_services`

### Process Analysis (1)
- `ps -A` — running processes

### Network Analysis (3)
- `netstat -tlnp` — listening ports
- `netstat -an | grep ESTABLISHED` — established connections
- `getprop net.dns1 && net.dns2 && net.dns3` — DNS configuration

### Account Analysis (1)
- `dumpsys account` — synced accounts

### System Integrity (2)
- `getprop ro.debuggable && ... && odsign.verification.success` — 9 security properties
- `getprop partition.system.verified.root_digest && ...` — 9 partition digests

### Hooking Detection (1)
- `ls /data/local/tmp/re.frida.server* && ... && which magisk && ls /data/adb/magisk` — 9 filesystem checks

### Memory Integrity (1)
- `cat /proc/self/maps | grep -E frida|xposed|substrate|hook`

### APK Verification (1)
- `pm verify com.whatsapp && ... && pm verify com.anydesk.anydeskandroid`

### System Certificates (1)
- `ls /system/etc/security/cacerts/`

### System Binaries (1)
- `ls /system/bin/ && ls /system/xbin/ && ls /sbin/`

### Filesystem Scan (1)
- `ls -la /data/local/tmp/`

### Init Services (1)
- `getprop | grep init.svc`

### AppOps Analysis (1)
- `dumpsys appops`

### Running Services (1)
- `dumpsys activity services`

### Window/Overlay (1)
- `dumpsys window windows`

### SMS/Call/Contact (3)
- `content query --uri content://sms`
- `content query --uri content://call_log/calls`
- `content query --uri content://contacts/phones`

### VPN/Proxy (1)
- `getprop global.http_proxy && getprop global.socks_proxy`

### Connectivity (1)
- `dumpsys connectivity`

### WiFi Info (1)
- `dumpsys wifi`

### Location (1)
- `dumpsys location`

### Battery (1)
- `dumpsys batterystats`

### Notifications (1)
- `dumpsys notification`

### Lock Settings (1)
- `dumpsys lock_settings`

### USB History (1)
- `dumpsys usb`

### Device Admin (1)
- `dumpsys device_policy`

### Security Event Logs (1)
- `logcat -d -b security`

### System Logs (1)
- `logcat -d -v time`

### Memory Usage (1)
- `dumpsys meminfo`

### APK Hashing (1)
- `sh /data/local/tmp/hash_apks.sh` (on-device script)

### WiFi MAC (1)
- `cat /sys/class/net/wlan0/address`

### SIM Country (1)
- `getprop gsm.sim.operator.iso-country && getprop gsm.operator.iso-country`

---

## JSON Report Schema

```json
{
  "timestamp": "2026-07-22 12:00:00 UTC",
  "device_serial": "BISG5XZL9LSWZXO7",
  "scanned_files": 4,
  "composite_risk_score": 0,
  "composite_risk_level": "CLEAN",
  "verdict": "CLEAN",
  "verdict_reasons": ["Weighted score band: CLEAN (0/100).", "..."],
  "yara_matches": [
    {
      "rule": "Frida_Hooking_Framework",
      "file": "netstat.log",
      "tags": ["frida", "hooking_framework"],
      "classification": "authorized_forensic_tooling",
      "confidence": 0.10,
      "authoritative": false,
      "context_reason": "YARA rule matches a known forensic analysis tool..."
    }
  ],
  "tool_status": { "mvt": "disabled", "osint": "ok", "openmf": "skipped_no_root", ... },
  "osint_lookups": [
    { "imei": "86758007****749", "sim_operator": "MAROC TELECOM", ... }
  ],
  "forensic_findings": [
    { "type": "SUSPICIOUS_PORT", "severity": "HIGH", "port": "27042", "reason": "frida_default" }
  ],
  "summary": "[CLEAN] DEVICE CLEAN\n\nScanned 4 forensic artifacts.\n..."
}
```

**IMEI privacy:** IMEI is masked by default in all JSON output (`86758007****749`).

---

## File Structure

```
SECURITY PHONE/
├── app.py                    # Tkinter GUI (Row 7: recommendations panel)
├── analyzer.py               # Core analysis engine (1587 lines)
├── extractor.py              # Manifest-driven ADB extraction
├── core.py                   # ADB runner, dump directory management
├── version.py                # VERSION = "7.0.0-rc1"
├── cli.py                    # CLI menu interface
├── heuristics.py             # Permission abuse heuristics
├── remediation_engine.py     # Remediation action generation
├── recommendations_engine.py # Prioritized recommendations + high-risk DB
├── correlation_engine.py     # Cross-tool event correlation
├── yara_context.py           # YARA match classification (forensic allowlist, dual-use)
├── yara_diagnostics.py       # Evidence collection for YARA matches
├── history_db.py             # Scan history, delta computation, SQLite
├── noise_filter.py           # Log noise reduction
├── scan_offline.py           # Offline bugreport analysis
├── report_generator.py       # Markdown report generation
├── mock_adb.py               # ADB simulation for testing
│
├── forensic_modules/         # NEW: Cellebrite-grade artifact analysis
│   ├── __init__.py
│   ├── system_integrity.py       # 7 security properties
│   ├── partition_verification.py # 9 partition digests
│   ├── signature_verification.py # APK signature verification
│   ├── network_forensics.py      # Suspicious ports, DNS audit
│   ├── account_analysis.py       # Synced accounts enumeration
│   └── proxy_vpn_detection.py    # HTTP/SOCKS proxy detection
│
├── adapters/                 # Device adapter registry
│   ├── base_adapter.py
│   └── android_adapter.py    # Android ADB adapter (loads forensic profile)
│
├── manifests/
│   ├── artifacts.json        # Legacy v2.1 (triage: 4, deep: 18)
│   └── android_artifacts.json # Unified v5.0 (triage: 4, deep: 18, forensic: 37)
│
├── rules/
│   └── poco_rules.yar        # 8 YARA rules (Frida, Xposed, Substrate, Magisk,
│                             #   Spyware, Remote Access, Data Exfil, Security Evasion)
│
├── iocs/
│   └── known_ips.json        # 25,954 known malicious IPs
│
├── external_tools/           # Optional forensic tools
│   ├── mvt_bridge.py
│   ├── mobsf_bridge.py       # MobSF REST API client
│   ├── openmf_bridge.py      # OpenMF wrapper
│   ├── osint_bridge.py       # Phone/IMEI/SIM extraction + OSINT URLs
│   ├── apkid_bridge.py
│   ├── quark_bridge.py
│   ├── capa_bridge.py
│   ├── aleapp_bridge.py
│   └── entropy_analyzer.py
│
├── domain/
│   └── scan_result.py        # Domain model for scan results
│
├── test_live.py              # Live device test script
├── test_heuristics.py        # Heuristic analysis tests
├── run_cli.bat               # CLI launcher
├── run_gui.bat               # GUI launcher
├── UniversalForensicScanner.spec  # PyInstaller build spec
│
├── docs/                     # 8 documentation files (French)
│   ├── GUIDE_UTILISATEUR.md
│   ├── GUIDE_ENQUETEUR.md
│   ├── GUIDE_INSTALLATION.md
│   ├── GUIDE_DEVELOPPEUR.md
│   ├── LIMITATIONS.md
│   ├── RELEASE_NOTES.md
│   ├── LICENCES.md
│   └── FULL_FORENSIC_REPORT.md
│
├── PROJECT_MAP.md
├── PROGRAM.md                # This file
└── README.md
```

---

## Build & Testing

### Build
```bat
pyinstaller UniversalForensicScanner.spec    # Dual EXE (GUI + CLI)
```
Requires Tcl/Tk 8.6 bundled from `C:\Users\imadfdl\AppData\Local\Programs\Python\Python312\tcl\`.

### Tests
```bat
venv\Scripts\pytest tests/ -v               # 22/22 pass
venv\Scripts\python mock_adb.py              # 15/15 pass
venv\Scripts\ruff check *.py                 # Lint clean
venv\Scripts\python test_live.py             # Live device test
```

---

## Known Limitations

| Limitation | Impact | Mitigation |
|-----------|--------|------------|
| Physical extraction requires root | Cannot extract encrypted databases | Use logical acquisition + MVT |
| Frida detected as suspicious in non-forensic context | Score inflation if forensic_context=False | Always pass forensic_context=True |
| OpenMF requires root | Skipped on non-rooted devices | Falls back to ADB-only extraction |
| MobSF requires Docker | Cannot run static APK analysis | MobSF results optional |
| IMEI masked by default | Cannot see full IMEI in reports | Full IMEI available in raw OSINTResult object |
| Partition digests are read-only | Cannot verify against known-good values | Detects missing/empty digests only |
| APK signature verification limited to 5 apps | Cannot verify all installed apps | Extend apk_signature command in manifest |

---

## Development Notes

### Adding a new forensic module
1. Create `forensic_modules/your_module.py` with a `check_*(content, source_file)` function
2. Return `list[dict]` with keys: `type`, `severity`, `evidence`, `file`
3. Import in `analyzer.py` and call from `_process_forensic_artifacts()`
4. The module receives the raw text content of the extracted artifact

### Adding a new YARA rule
1. Edit `rules/poco_rules.yar`
2. Add rule with `meta: severity`, `strings:`, `condition:`
3. Tags determine classification: use `frida`/`hooking_framework` for allowlisted tools
4. Package names in strings trigger dual-use classification automatically

### Modifying risk scoring
Composite risk buckets are in `_compute_composite_risk()` (analyzer.py:895-1047).
Point values: `_YARA_SEVERITY_POINTS = {"CRITICAL": 35, "HIGH": 22, "MEDIUM": 12, "LOW": 5}`.
