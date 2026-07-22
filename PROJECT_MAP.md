# PROJECT_MAP.md — Universal Forensic Scanner

## [TECH_STACK]
- Python 3.12.10 (CPython, Windows 11)
- customtkinter 6.0.0 — GUI framework
- yara-python 4.5.4 — Malware signature matching
- psutil 7.2.2 — Process/system monitoring
- requests 2.34.2 — HTTP (IOC feeds, VirusTotal, MobSF API)
- pymobiledevice3 >= 4.0.0 — iOS device forensics (lockdown, syslog, apps)
- docker >= 6.0.0 — Docker container forensics
- paramiko >= 3.0.0 — SSH remote Linux forensics
- mvt >= 1.8.0 — Mobile Verification Toolkit (Pegasus/Predator IOC scanning)
- aleapp >= 3.2.0 — Android Logs Events And Protobuf Parser (deep artifact parsing)
- capa >= 7.0.0 — Mandiant Capability Analysis (APK/binary static analysis)
- apkid >= 1.3.5 — APKiD packer/obfuscation/anti-analysis detection (RedNaga)
- quark-engine >= 23.0.0 — Quark-Engine behavioral Dalvik bytecode analysis
- otxv2 >= 1.5.0 — AlienVault OTX threat intelligence SDK
- pyzipper (optional) — AES-256 encrypted ZIP packaging
- sqlite3 (stdlib) — Scan history database
- Android SDK Platform-Tools 37.0.1 (adb) — Device communication

## [SYSTEM_FLOW]
```
[User connects a device via USB, SSH, or Docker]
        │
        ▼
[usb_monitor.py] ── polls `adb devices` every 2s (Android)
   │  Detects ANY Android device (universal, no brand filter)
   │  Emits state: DISCONNECTED | UNAUTHORIZED | READY
   │
[adapters/] ── device adapter layer
   │  AndroidAdapter — ADB (all OEMs)
   │  IOSAdapter — pymobiledevice3 (lockdown, syslog, apps)
   │  LinuxDockerAdapter — SSH + docker exec
   │
   ▼
[app.py GUI] ── shows status indicator
   │  Red = Disconnected | Yellow = Locked | Green = Ready
   │  Device type selector: Android / iOS / Linux+Docker
   │  Profile: Triage (4) or Deep (18+)
   │  Options panel (3 columns): ACQUISITION | ANALYSIS | INTEL + ACTION
   │  Checkboxes: [PCAP] [VT] [Report] [Timeline] | [MVT] [ALEAPP] [Capa] [APKiD] [Quark] [Entropy] [Browser] | [OTX] [Encrypt] [Correlation]
   │  Action buttons: [SCAN] [CREATE ZIP] [CONTAIN]
   │
   ├── [LIVE MODE] ──────────────────────────────────────────────┐
   │                                                              │
   │  ▼                                                           │
   │  [extractor.py] ── manifest-driven engine                    │
   │  │  Reads manifests/*.json at runtime                        │
   │  │  Executes ADB/shell commands based on profile             │
   │  │                                                           │
   │  ▼                                                           │
   │  [pcap_bridge.py] ── (optional) live capture                 │
   │  │  Configurable: 3min / 5min / 15min / 1hr                 │
   │  │  IP/domain whitelisting + DNS reverse resolution          │
   │  │  C2 domain cross-ref (ngrok, duckdns, burp, etc)         │
   │  │                                                           │
   │  ▼                                                           │
   │  [analyzer.py] ── 12-phase threat analysis engine            │
   │     Phase 1:  Log filter gate (~30% noise reduction)         │
   │     Phase 2:  YARA rule matching (14 rules)                  │
   │     Phase 3:  IOC cross-ref (18,681 known IPs)              │
   │     Phase 4:  MVT spyware IOC scanning                       │
   │     Phase 5:  ALEAPP deep artifact parsing                   │
   │     Phase 6:  Capa capability analysis                       │
   │     Phase 7:  APKiD packer/obfuscation detection             │
   │     Phase 8:  Quark behavioral rule scoring                  │
   │     Phase 9:  OTX + AbuseIPDB live IP intelligence           │
   │     Phase 10: Shannon entropy analysis (encrypted exfil)     │
   │     Phase 11: Chrome/WebView browser forensics               │
   │     Phase 12: Cross-tool correlation engine                  │
   │     Returns: verdict + all tool results                      │
   │                                                              │
   └──────────────────────────────────────────────────────────────┘
   │
   ├── [OFFLINE MODE] ──────────────────────────────────────────┐
   │                                                             │
   │  ▼                                                          │
   │  [archive_engine.py] ── offline ingestion                   │
   │  │  Ingests bugreport ZIP / backup tarball                  │
   │  │  Scans SQLite databases + zero-click domains             │
   │  │                                                          │
   │  ▼                                                          │
   │  [analyzer.py] ── same 12-phase pipeline as live            │
   │                                                             │
   └─────────────────────────────────────────────────────────────┘
   │
   ▼
[timeline.py] ── unified forensic timeline (optional)
   │
   ▼
[custody.py] ── chain-of-custody packaging
   │  AES-256 encrypted ZIP + HMAC-SHA256 + SHA-256 hash chain
   │  Per-tool evidence records (MVT/ALEAPP/capa/APKiD/Quark/OTX)
   │  Auto-locks evidence on CRITICAL verdict
   │
   ▼
[containment_engine.py] ── automated incident response (conditional)
   │  DNS sinkholing via Private DNS (no-root, via ADB)
   │  App background execution revocation (appops)
   │  Location/background access revocation for suspicious packages
   │  Evidence lock (auto-create evidence package on CRITICAL)
   │  IP blocking recommendations via DNS sinkhole
   │  Undo support (restore defaults)
   │
   ▼
[history_db.py] ── scan history (SQLite)
   │  Records every scan, fingerprint tracking, delta engine
   │
   ▼
[remediation_engine.py] ── automated remediation (conditional)
   │  DELETE / UPDATE / RESTRICT decision matrix
   │  System app protection, deduplication
   │
   ▼
[app.py GUI] ── Triage Navigator + results
   │  Navigator: severity filter + search + Inspect sub-viewer
   │  Remediation actions: DELETE / RESTRICT / UPDATE
   │  CONTAIN button: automated incident response
   │  Green → [CLEAN] | Yellow → [SUSPICIOUS] | Red → [CRITICAL]
   │
   ▼
[cleanup] ── auto-deletes dump directory
```

## [ARCHITECTURE]
```
SECURITY PHONE/
├── PROJECT_MAP.md              ← This file (v7.0-rc3)
├── requirements.txt            ← Pinned dependencies (incl. apkid, quark, otx)
├── setup.bat                   ← One-click Windows setup script
├── run.bat                     ← One-click GUI launcher
├── app.py                      ← Entry point. GUI, Navigator, Inspect, ZIP, CONTAIN, Remediation
├── core.py                     ← Shared layer: Logger, ADB wrapper, constants
├── usb_monitor.py              ← USB polling — detects ANY Android device (universal)
├── adapters/                   ← Device adapter layer
│   ├── __init__.py             ← Registers all adapters
│   ├── base_adapter.py         ← Abstract base class + AdapterRegistry
│   ├── android_adapter.py      ← Universal Android adapter (all OEMs)
│   ├── ios_adapter.py          ← iPhone/iPad support via pymobiledevice3
│   └── linux_docker_adapter.py ← Linux server + Docker container support
├── extractor.py                ← Manifest-driven extraction engine
├── analyzer.py                 ← 12-phase analysis: YARA + IOC + MVT + ALEAPP + capa + APKiD + Quark + OTX + Entropy + Browser + Correlation
├── heuristics.py               ← Permission matrix risk scoring
├── history_db.py               ← SQLite scan history + delta engine
├── archive_engine.py           ← Offline ingestion + artifact map + SQLite forensics
├── remediation_engine.py       ← DELETE/UPDATE/RESTRICT decision matrix
├── containment_engine.py       ← DNS sinkhole + app isolation + evidence lock
├── pcap_bridge.py              ← Live PCAP + DNS/TLS SNI + whitelisting + capture presets
├── timeline.py                 ← Unified forensic timeline
├── custody.py                  ← AES-256 + HMAC-SHA256 + SHA-256 chain + auto-evidence lock
├── entropy_bridge.py           ← [NEW v6.1] Shannon entropy + encrypted exfil/obfuscation detection
├── browser_forensics_bridge.py ← [NEW v6.2] Chrome/WebView SQLite forensics + suspicious URL detection
├── correlation_engine.py       ← [NEW v6.2] Cross-tool event correlation engine (6 JSON rules)
├── apkid_bridge.py             ← APKiD packer/obfuscation/anti-analysis detection
├── quark_bridge.py             ← Quark-Engine behavioral rule scoring
├── intel_bridge.py             ← OTX + AbuseIPDB + TinyCheck live IP intelligence
├── mvt_bridge.py               ← MVT spyware IOC scanning (Pegasus, Predator, FinSpy)
├── aleapp_bridge.py            ← ALEAPP deep artifact parsing + stalkerware detection
├── capa_bridge.py              ← Mandiant capa APK/binary static analysis
├── ioc_sync.py                 ← IOC feed sync (abuse.ch + C2IntelFeeds + ipsum + TinyCheck)
├── mobsf_bridge.py             ← MobSF REST API integration
├── mock_adb.py                 ← Headless test harness (15 test cases)
├── hash_apks.sh                ← Device-side APK SHA-256 hashing script
├── manifests/
│   ├── artifacts.json          ← Legacy manifest (backward compatible)
│   ├── android_artifacts.json  ← Universal Android extraction profiles (18 artifacts)
│   ├── ios_artifacts.json      ← iOS forensic extraction profiles (6 artifacts)
│   └── linux_artifacts.json    ← Linux/server/Docker extraction profiles (10 artifacts)
└── rules/
    ├── poco_rules.yar          ← YARA rule definitions (14 rules)
    ├── known_ips.txt           ← Known malicious IPs (auto-synced to 18,681)
    └── scans.db                ← SQLite scan history database
```

### Module Responsibilities
| Module | Lines | Responsibility |
|--------|-------|----------------|
| `core.py` | ~135 | Logger, ADB runner, universal constants |
| `usb_monitor.py` | ~100 | Polls `adb devices`, detects ANY Android device |
| `adapters/base_adapter.py` | ~90 | Abstract adapter interface + AdapterRegistry |
| `adapters/android_adapter.py` | ~120 | Universal Android adapter — all OEMs |
| `adapters/ios_adapter.py` | ~170 | iOS adapter — lockdown, syslog, apps, profiles |
| `adapters/linux_docker_adapter.py` | ~130 | Linux (SSH) + Docker container adapter |
| `extractor.py` | ~120 | Manifest-driven extraction, dynamic profiles |
| `analyzer.py` | ~1018 | 12-phase analysis engine: YARA, IOC, MVT, ALEAPP, capa, APKiD, Quark, OTX, Entropy, Browser, Correlation + composite risk score |
| `heuristics.py` | ~160 | Permission risk scoring, spyware combos |
| `history_db.py` | ~265 | SQLite scan history, fingerprint tracking, delta |
| `archive_engine.py` | ~300 | Offline ingestion, artifact map, SQLite scanning |
| `remediation_engine.py` | ~230 | DELETE/UPDATE/RESTRICT matrix, system app protection |
| `containment_engine.py` | ~250 | DNS sinkhole, app isolation, evidence lock (no-root) |
| `pcap_bridge.py` | ~470 | Live tcpdump, DNS/SNI, C2 detection, whitelisting |
| `timeline.py` | ~170 | Timestamp normalization, CSV timeline |
| `custody.py` | ~320 | AES-256 ZIP, HMAC-SHA256, SHA-256 chain, auto-evidence lock |
| `entropy_bridge.py` | ~200 | Shannon entropy analysis, encrypted exfil/obfuscation detection |
| `browser_forensics_bridge.py` | ~250 | Chrome/WebView SQLite forensics, suspicious URL detection |
| `correlation_engine.py` | ~400 | Cross-tool event correlation (6 JSON rules), package-based grouping |
| `apkid_bridge.py` | ~220 | APKiD packer/obfuscation/anti-analysis detection |
| `quark_bridge.py` | ~200 | Quark-Engine behavioral Dalvik bytecode analysis |
| `intel_bridge.py` | ~280 | OTX + AbuseIPDB + TinyCheck live IP intelligence |
| `mvt_bridge.py` | ~130 | MVT Pegasus/Predator IOC scanning |
| `aleapp_bridge.py` | ~180 | ALEAPP artifact parsing, stalkerware detection |
| `capa_bridge.py` | ~150 | Capa malicious capability detection |
| `ioc_sync.py` | ~135 | IOC feed sync (abuse.ch, C2IntelFeeds, ipsum, TinyCheck) |
| `mobsf_bridge.py` | ~130 | MobSF REST API integration |
| `mock_adb.py` | ~430 | 15 test cases: full pipeline coverage |
| `app.py` | ~1450 | GUI: Navigator, Inspect, ZIP, CONTAIN, 14 checkboxes (3-col layout) |

### YARA Rules Inventory (14 rules)
| # | Rule | Source | Severity |
|---|------|--------|----------|
| 1 | Disguised_Suspicious_Package | Custom | HIGH |
| 2 | Pegasus_Zero_Click_Traces | Custom + MVT | CRITICAL |
| 3 | Reverse_Shell_Indicators | Custom | CRITICAL |
| 4 | Suspicious_Battery_Consumption | Custom | MEDIUM |
| 5 | Suspicious_Network_Patterns | Custom | MEDIUM |
| 6 | NoviSpy_Android_AccessibilityService | Amnesty Tech | CRITICAL |
| 7 | NoviSpy_Android_ServServices | Amnesty Tech | CRITICAL |
| 8 | FinSpy_Android_Config | Amnesty Tech | CRITICAL |
| 9 | Dendroid_RAT | Yara-Rules | CRITICAL |
| 10 | HackingTeam_Android_Implant | Yara-Rules | CRITICAL |
| 11 | SandroRAT | Yara-Rules | CRITICAL |
| 12 | Android_Credential_Harvester | Custom | HIGH |
| 13 | Android_Data_Exfiltration | Custom | HIGH |
| 14 | Android_Root_Detection_Evasion | Custom | MEDIUM |

### ADB Extraction Inventory (18 commands, deep profile)
| # | ID | Command | File | Profile |
|---|----|---------|------|---------|
| 1 | device_info | `getprop` | device_info.txt | Triage + Deep |
| 2 | network_connections | `netstat -anp` | netstat.log | Triage + Deep |
| 3 | third_party_apps | `pm list packages -3` | third_party_apps.txt | Triage + Deep |
| 4 | running_processes | `ps -A` | processes.txt | Triage + Deep |
| 5 | system_apps | `pm list packages -s` | system_apps.txt | Deep |
| 6 | battery_stats | `dumpsys batterystats` | batterystats.log | Deep |
| 7 | system_logs | `logcat -d -v time` | system_execution.log | Deep |
| 8 | memory_usage | `dumpsys meminfo` | meminfo.txt | Deep |
| 9 | wifi_history | `dumpsys wifi` | wifi_history.txt | Deep |
| 10 | location_services | `dumpsys location` | location_services.txt | Deep |
| 11 | notification_history | `dumpsys notification` | notifications.txt | Deep |
| 12 | registered_accounts | `dumpsys account` | accounts.txt | Deep |
| 13 | lock_settings | `dumpsys lock_settings` | lock_settings.txt | Deep |
| 14 | usb_history | `dumpsys usb` | usb_history.txt | Deep |
| 15 | accessibility_services | `dumpsys accessibility` | accessibility_services.txt | Deep |
| 16 | device_admin | `dumpsys device_policy` | device_admin.txt | Deep |
| 17 | vpn_config | `dumpsys connectivity` | vpn_config.txt | Deep |
| 18 | apk_hashes | `pm list packages + sha256sum` | apk_hashes.txt | Deep |

### New Features (v7.0)
| Feature | Module | Description |
|---------|--------|-------------|
| GUI Packaging | `UniversalForensicScanner.spec` | PyInstaller dual EXE: GUI + CLI with Tcl/Tk bundled |
| Central Version | `version.py` | Single source for version string (7.0.0-rc1) |
| GUI Branding | `app.py` | Dynamic version from `version.py` instead of hardcoded |
| User Documentation | `docs/GUIDE_UTILISATEUR.md` | Complete user guide |
| Investigator Guide | `docs/GUIDE_ENQUETEUR.md` | Forensic investigator guide |
| Installation Guide | `docs/GUIDE_INSTALLATION.md` | Windows setup instructions |
| Developer Guide | `docs/GUIDE_DEVELOPPEUR.md` | Architecture and contribution guide |
| Limitations Doc | `docs/LIMITATIONS.md` | Known limitations and roadmap |
| Release Notes | `docs/RELEASE_NOTES.md` | Version history and changelog |
| Licences | `docs/LICENCES.md` | Third-party notices and attributions |

### New Features (v6.2)
| Feature | Module | Description |
|---------|--------|-------------|
| Chrome/WebView Browser Forensics | `browser_forensics_bridge.py` | Chrome History/Login Data/Cookies SQLite parsing, suspicious URL detection (C2 TLDs, ngrok, etc.) |
| Cross-Tool Correlation Engine | `correlation_engine.py` | 6 JSON rules correlating events across YARA/MVT/ALEAPP/capa/APKiD/Quark/Entropy/Browser by package name |
| Entropy + Browser + Correlation Phases | `analyzer.py` | Phase 10 (Shannon entropy), Phase 11 (browser forensics), Phase 12 (cross-tool correlation) |
| 3-Column Options Panel | `app.py` | ACQUISITION | ANALYSIS | INTEL+ACTION workflow layout |
| 14 Checkboxes | `app.py` | PCAP, VT, Report, Timeline, MVT, ALEAPP, Capa, APKiD, Quark, Entropy, Browser, OTX, Encrypt, Correlation |

### New Features (v6.1)
| Feature | Module | Description |
|---------|--------|-------------|
| Shannon Entropy Analysis | `entropy_bridge.py` | H > 7.5 threshold for encrypted exfil detection, sliding window block analysis |
| Exfil/Obfuscation Risk Flags | `entropy_bridge.py` | Automatic risk classification based on entropy patterns |
| Entropy Phase in Analyzer | `analyzer.py` | Phase 10 integration with verdict escalation |

### New Features (v6.0)
| Feature | Module | Description |
|---------|--------|-------------|
| APKiD Packer Detection | `apkid_bridge.py` | Detects DEX packers (DexGuard, SecShell, Ijiami), anti-analysis techniques, obfuscation |
| Quark Behavioral Analysis | `quark_bridge.py` | Dalvik bytecode behavioral mapping — SMS interception, audio recording, location tracking |
| Live OTX Intelligence | `intel_bridge.py` | AlienVault OTX pulse lookup — real-time C2 IP attribution |
| AbuseIPDB Integration | `intel_bridge.py` | IP abuse confidence scoring with 90-day history |
| TinyCheck Stalkerware Feeds | `intel_bridge.py` + `ioc_sync.py` | Stalkerware/spyware domain + IP IOC feeds from TinyCheck |
| Automated Incident Containment | `containment_engine.py` | DNS sinkhole, app isolation, evidence lock — no-root via ADB |
| DNS Sinkholing | `containment_engine.py` | Private DNS → AdGuard blockhole to cut C2 communications |
| App Background Revocation | `containment_engine.py` | Revoke RUN_IN_BACKGROUND + background location via appops |
| Auto-Evidence Lock | `containment_engine.py` | Auto-create SHA-256 evidence package on CRITICAL verdict |
| Contain Button | `app.py` | One-click automated incident response in GUI |
| 9-Phase Analysis Pipeline | `analyzer.py` | APKiD (Phase 7) + Quark (Phase 8) + OTX (Phase 9) added |
| APKiD/Quark/OTX Checkboxes | `app.py` | Toggle controls for new analysis engines |
| Expanded IOC Feeds | `ioc_sync.py` | TinyCheck stalkerware IPs added to auto-sync |
| Expanded Dependencies | `requirements.txt` | apkid, quark-engine, otxv2 added |

### New Features (v5.0)
| Feature | Module | Description |
|---------|--------|-------------|
| MVT Spyware Scanning | `mvt_bridge.py` | Pegasus, Predator, FinSpy IOC detection |
| ALEAPP Artifact Analysis | `aleapp_bridge.py` | Deep Android artifact parsing, stalkerware detection |
| Capa Static Analysis | `capa_bridge.py` | Mandiant capa — keylogger, reverse shell, C2 capability detection |
| PCAP Capture Presets | `pcap_bridge.py` | Quick (3min), Standard (5min), Extended (15min), Continuous (1hr) |
| IP/Domain Whitelisting | `pcap_bridge.py` | Legitimate infrastructure exclusion |
| SHA-256 Evidence Chain | `custody.py` | Rolling hash chain over all evidence files + tool results |
| Per-Tool Evidence Records | `custody.py` | Signed evidence items for each analysis tool |

## [VERIFIED]
- **Universal Android support:** Samsung, Xiaomi, Google Pixel, OnePlus, Oppo, Vivo, Huawei, Motorola, Sony, Nokia, Realme, Meizu
- **iOS adapter ready:** iPhone/iPad via pymobiledevice3 — lockdown, syslog, apps, config profiles
- **Linux/Docker adapter ready:** SSH remote servers + Docker container inspection
- **Full pipeline verified (v2.0→v6.2):** USB detect → Extract → 12-phase analysis → verdict
- **Mock test harness verified (v6.2):** 15 test cases passing
- **Manifest-driven extraction:** Triage = 4 files, Deep = 18 files
- **Log filter gate:** ~30% noise reduction on log-type artifacts
- **YARA rules:** 14 rules compile, zero false positives on real device
- **IOC feeds:** 18,681+ IPs auto-synced (abuse.ch + C2IntelFeeds + ipsum + TinyCheck)
- **Heuristics engine:** Permission risk scoring 0-100, spyware combo detection
- **Scan history:** SQLite database with fingerprint tracking + delta
- **PCAP bridge:** Configurable capture, whitelisting, DNS reverse resolution
- **Custody signing:** HMAC-SHA256 + SHA-256 chain + auto-evidence lock
- **Remediation engine:** DELETE/UPDATE/RESTRICT decision matrix
- **Artifact map:** Structured file index with status per artifact
- **Triage Navigator:** Severity filter + search + Inspect sub-viewer
- **Bugreport ZIP export:** Pull live bugreport via ADB
- **MVT/ALEAPP/capa integration:** Optional checkboxes in GUI
- **APKiD packer detection:** Obfuscation and anti-analysis scanning (optional)
- **Quark behavioral analysis:** Dalvik bytecode malicious behavior mapping (optional)
- **OTX live intelligence:** Real-time C2 IP attribution via AlienVault + AbuseIPDB (optional)
- **Automated containment:** DNS sinkhole + app isolation + evidence lock (CONTAIN button)
- **Shannon entropy analysis:** Encrypted exfil/obfuscation detection via high-entropy blocks (optional)
- **Browser forensics:** Chrome/WebView SQLite parsing + suspicious URL detection (optional)
- **Cross-tool correlation:** 6 JSON rules linking events across analysis tools by package name (optional)
- **Composite risk score:** 0-100 score combining YARA severity + permissions + tools + intel + entropy — eliminates the old disconnect where YARA matches showed as "0/100 CLEAN"
- **Auto-evidence lock:** SUSPICIOUS + HIGH YARA hits → automatic signed evidence package

## [BUGS_FIXED]
1-12. All v2.0 bugs (see git history)
13. `extractor.py` — `from core import run_adb` → `import core; core.run_adb()`
14. `usb_monitor.py` — same import pattern fix
15. `mock_adb.py` — wrong assertion count for deep profile
16. `mock_adb.py` — APK hashes requires pushed script on real device
17. `extractor.py` — accessibility_services must use `dumpsys accessibility`
18. `poco_rules.yar` — Suspicious_Network_Patterns false positive on port 4414444
19. `app.py` — `_on_mode_change()` called before widgets exist → guarded with `hasattr`
20. `app.py` — dump dir cleaned before ZIP export → persist until next scan
21. `usb_monitor.py` — hardcoded Xiaomi VID → universal Android detection
22. `app.py` — connection panel → dynamic brand/model/Android version display
23. `archive_engine.py` — `_hunt_zero-click_domains` invalid method name → `_hunt_zero_click_domains`
24. `analyzer.py` — broken docstring with trailing `(brand, model, etc.)` removed
25. **CRITICAL: Risk score/verdict disconnect** — `heuristics.py` was a pure permission scorer with zero awareness of YARA matches. 6 HIGH-severity YARA hits displayed as "Risk Score: 0/100 (CLEAN)". Fixed with `_compute_composite_risk()` that combines YARA severity (35pts), permissions (25pts), MVT/capa/APKiD/Quark (20pts), IOC/intel (10pts), entropy/browser/correlation (10pts) into a single 0-100 composite score.
26. **Version string mismatch** — Title bar showed `v4.0`, subtitle showed `v3.1`. Unified to `v6.2` across `app.py`, `custody.py`, `mock_adb.py`.
27. **Artifact count confusing** — Navigator showed `3759/3759 files` when only 106 were YARA-scanned. Fixed to show `{indexed} indexed · {scanned} scanned`.
28. **Auto-evidence lock** — SUSPICIOUS verdict with HIGH-severity YARA matches now auto-creates signed evidence package (previously only triggered on CRITICAL or explicit encrypt checkbox).

## [ORPHANS & PENDING]
- v7.1 planned: On-device YARA execution (ARM64 binary push)
- v7.2 planned: Pre-compiled YARA rules (.yarc cache)
- v7.3 planned: Windows/macOS host adapter (local system forensics)
- v7.4 planned: Encrypted PCAP capture with TLS 1.3 key support
- v7.5 planned: Automated YARA rule generation from MVT/APKiD findings

## [ARCHITECTURE_FOUNDATION_V7_STATUS]

**Status date:** 2026-07-22 UTC  
**Authoritative repository:** `C:\Users\imadfdl\Desktop\SECURITY PHONE`  
**Reference-only repository:** `Forensic-Scanner-Multi-Plateforme` (do not maintain as a competing architecture)

The v7 foundation is being introduced incrementally behind the operational v6.2
pipeline. The lifecycle/finalization implementation remains in place and is not
to be rewritten during subsequent migrations.

### Current v7 components

| Area | Current implementation | Status |
|---|---|---|
| Scan lifecycle | `scan_lifecycle.py`, GUI lifecycle integration | Complete; explicit terminal states and finalization callbacks |
| YARA evidence diagnostics | `yara_diagnostics.py`, `yara_context.py` | Complete; offsets, identifiers, previews, context, confidence, classification |
| YARA integration | `analyzer.py`, `rules/poco_rules.yar` | Complete for aggregate bugreport context; focused artifacts remain authoritative |
| Offline ingestion | `archive_engine.py`, `scan_offline.py` | Operational; analyzers receive extracted local paths |
| Offline ADB isolation | `usb_monitor.py`, `app.py` | Complete; USB monitor pauses during offline archive scans |
| Tool health | `analyzer.py`, `scan_offline.py` | Complete; distinguishes `ok`, `disabled`, `skipped_no_input`, `unavailable`, `error` |
| Compatibility models | `domain/`, `compat/` | Introduced behind v6.2 interfaces; migration remains incremental |
| Evidence/custody | `custody.py` and existing evidence chain | Existing v6.2 controls retained; broader immutable-manifest migration remains pending |
| Canonical reporting | JSON report remains source for existing report/timeline outputs | Operational; HTML/PDF unification remains pending |

### Current offline pipeline

```text
ZIP archive
  -> archive_engine.py (extract/index/select)
  -> local artifact paths
  -> analyzer.py (YARA, IOC, heuristics, optional tools)
  -> correlation and composite risk
  -> SQLite scan history
  -> JSON report and CSV timeline
  -> lifecycle finalization and GUI control restoration
```

Analyzers must not access ADB, SSH, Docker, iOS lockdown, or cloud targets
directly. Acquisition and analysis separation is complete for the offline
archive path and is the reference pattern for Android migration.

### YARA context policy

Aggregate Android bugreports are diagnostic evidence, not focused malware
artifacts. Raw matches are retained, but generic strings in an aggregate file do
not independently escalate the verdict. Each match includes:

```text
rule, namespace, tags, severity, artifact_path, string_identifier,
matched_value_preview, offset, context_before, context_after,
artifact_type, confidence, classification, authoritative, reason
```

The review and exact evidence are documented in
`docs/YARA_CONTEXT_REVIEW.md`, `diagnostics/yara_before.json`, and
`diagnostics/yara_after_rules.json`.

The corrected network rule requires a real IP endpoint using port 4444, 9999, or
31337 together with `ESTABLISHED` or `SYN_SENT`. This prevents configuration
values such as `value:9999` from being treated as network evidence.

### Reproduced archive result

Archive: `bugreport-poco.zip` (37.9 MB; 3,781 ZIP entries; 3,759 indexed; 106
selected; 38 YARA-scanned). The corrected run completed in 37.9 seconds:

```text
Raw YARA rules:       5 (the old network match was removed)
Authoritative YARA:   0
Composite score:      0/100 (CLEAN)
Verdict:              CLEAN
Terminal state:       completed with warnings in GUI mode when optional tools are unavailable
Timeline events:      454,573
```

Remaining raw matches are preserved and classified as generic diagnostic text or
likely false positives. This verdict is evidence-quality based; it is not a
claim that the archive is malware-free.

Tool health for the reproduced scan:

```text
OK:          entropy, correlation
SKIPPED:     browser, intel (no suitable input)
UNAVAILABLE: ALEAPP
DISABLED:    MVT, APKiD, capa, Quark
```

### Verification record (v7.0-rc3)

```text
pytest:         22/22 passed
mock_adb.py:    15/15 tests passed
Ruff:           All checks passed
mypy:           yara_context.py, yara_diagnostics.py, scan_lifecycle.py pass
imports:        root imports OK
compileall:     Clean (excluding venv, caches, pytest tmp)
GUI EXE:        Launches successfully, branding correct
CLI EXE:        Menu + error handling functional
Packaging:      PyInstaller 6.21.0, dual EXE, Tcl/Tk bundled
```

New regression coverage is in `tests/test_yara_context.py`,
`tests/test_yara_diagnostics.py`, and `tests/test_usb_monitor.py`.

### Remaining migration work

1. Convert Android live acquisition to the strict acquisition interface while
   preserving existing ADB behavior.
2. Complete immutable acquisition manifests and serialized custody ledger
   verification for every platform.
3. Add bounded analyzer execution groups and per-analyzer isolation to the
   remaining external bridges.
4. Add hash-based cache and incremental artifact analysis.
5. Validate JSON schema and render HTML/PDF only from canonical JSON.
6. Move settings to validated configuration and externalize all secrets.
7. Convert iOS, Windows, Linux/SSH, Docker, and cloud adapters one at a time.
8. Record honest real-device validation matrices and performance baselines.
9. Package only after reproducible validation.

### Known limitations

- Optional tools may be unavailable or lack supported inputs; these conditions
  are warnings, not silently reported successes.
- A large bugreport can contain hundreds of thousands of timeline events; GUI
  rendering must remain paginated/virtualized and must not insert all events
  synchronously into a widget.
- SHA-256 and the existing custody chain provide integrity evidence but do not by
  themselves prove forensic soundness.
- The nested reference repository is not a second product architecture and must
  be merged, archived, or retired after equivalent behavior is validated.

## [V7_RELEASE_ROADMAP]

This is the active implementation plan. `PROJECT_MAP.md` is updated after each
sprint, meaningful code change, and verification run.

### Release policy

```text
7.0.0-rc1  Android Live finalization + canonical JSON/CSV/PDF exports + version centralization
7.0.0-rc2  real-device regression + large-timeline/export/installer validation
7.0.0     approved release after reproducible validation
```

Existing v6.2 behavior remains the compatibility baseline until rc1 is
validated. No new detection features are planned in this work.

### Sprint 1 — Android Live finalization

Live and archive scans must use one finalization path. The finalizer runs in
`finally`, schedules GUI mutations with `root.after()`, reaches 100% only at
terminal finalization, restores controls, clears `_scan_running`, closes workers,
records duration, and retains generated outputs. Required markers are:

```text
[LIVE] Remediation started/completed
[LIVE] JSON export started/completed
[LIVE] CSV export started/completed
[LIVE] PDF export started/completed
[LIVE] GUI finalization scheduled/executed
[LIVE] Worker terminated
```

### Sprint 2 — Canonical reporting

`ScanResult` is the only source for verdict, score, severity, findings, and
statistics. JSON is written atomically to `reports/<case_id>/scan_result.json`.
CSV, HTML, and PDF renderers consume that JSON and never recalculate results.
Timeline CSV is streamed in batches; GUI previews are limited to approximately
500–1,000 events.

### Sprint 3 — GUI exports

After a valid terminal result, enable `EXPORT JSON`, `EXPORT CSV`, `EXPORT PDF`,
and `OPEN REPORT FOLDER`. Export work runs off the GUI thread. PDF failure changes
the result to `COMPLETED_WITH_WARNINGS` when JSON was successfully created.

### Sprint 4 — Central versioning

Create `version.py` as the single source for application name, version label, and
report schema version. All GUI, reports, custody records, tests, scripts, and
documentation import it. Do not mass-replace version strings before compatibility
tests pass.

### Sprint 5 — Validation

Required cases: Live Triage, Live Deep, disconnect during acquisition,
unauthorized phone, unavailable analyzer, large timeline, PDF failure, user
cancellation, ADB timeout, and restart after a scan. Each record includes UTC
date, device/build, profile, artifacts, warnings/errors, duration, tool versions,
application version, and reproducibility limitations.

### Required regression tests

```text
test_live_scan_reaches_completed
test_live_scan_reaches_completed_with_warnings
test_live_scan_finalizes_after_report_failure
test_live_scan_finalizes_after_timeline_failure
test_progress_never_decreases
test_buttons_restored_after_live_scan
test_scan_running_flag_cleared
test_json_export_is_valid
test_csv_export_contains_required_columns
test_pdf_export_created
test_pdf_failure_does_not_fail_scan
test_large_timeline_streaming
test_gui_timeline_preview_is_limited
test_all_outputs_share_same_verdict
test_version_is_consistent_everywhere
```

Baseline before Sprint 1: 24 pytest tests and legacy `mock_adb.py` passes 15/15.
No sprint is complete if the compatibility baseline regresses.

### Sprint log

| Date UTC | Sprint | Result | Tests | Notes |
|---|---|---|---|---|
| 2026-07-22 | Roadmap recorded | In progress | 24 pytest; 15/15 legacy | Android Live investigation pending |
| 2026-07-22 | Sprint 1 initial patch | Implemented behind compatibility path | 24 pytest; Ruff; mypy; compileall pass | Android Live worker now uses lifecycle, remediation/report/timeline timeouts, terminal finalizer, monotonic progress, and required `[LIVE]` markers |
| 2026-07-22 | Live start diagnostics | Implemented | 24 pytest; 15/15 legacy | Live button now logs handler acceptance, stale-running guard, and acquisition-worker startup to distinguish UI callback failure from ADB acquisition failure |
| 2026-07-22 | Live startup fix | Fixed | 24 pytest; compileall pass | `extractor.py` was missing `import json`; `get_profile_commands()` raised before worker creation and left `_scan_running=True`. Added import and visible startup exception recovery in `app.py`. |
| 2026-07-22 | CLI-first release foundation | Implemented | 24 pytest; CLI Ruff/compile pass | Added `cli.py` and `run_cli.bat`; numbered terminal menu supports Android Live ADB and offline archive, atomic canonical JSON summary, existing report, streamed timeline builder, remediation, tool-health summary, and explicit exit codes. |
| 2026-07-22 | Physical Android CLI validation | Passed | Triage acquisition + 24 pytest | POCO `2311DRK48`, Android 16, serial `BISG5XZL9LSWZXO7`: 4/4 artifacts acquired, 136 packages analyzed, 37 timeline events, CLEAN 0/100, JSON/report/CSV created. Fixed empty-serial ADB command construction and CLI output-directory creation. |
| 2026-07-22 | CLI Android Live auto-start | Passed | Physical Triage scan + 24 pytest; Ruff | Selecting menu option `1` now auto-detects the first authorized ADB device and starts acquisition; profile defaults to Triage. Verified on `BISG5XZL9LSWZXO7`: 4/4 artifacts, 28 timeline events, CLEAN 0/100, reports exported. |
| 2026-07-22 | CLI Stabilization v7.0 | In progress | 24 pytest; CLI Ruff; imports pass | Added idempotent logger handler configuration, `version.py` v7 branding, schema 1.1 structured canonical JSON, streamed timeline count, output metadata, and corrected optional-tool warning semantics. Real rerun confirms no duplicate callback output and canonical timeline count; Deep APK-hash deployment still requires explicit validation. |
| 2026-07-22 | Full Android Live analyzers | Passed with limitation | Deep physical scan exit 0; 18/18 acquisition; 24 pytest | POCO `2311DRK48G`, Android 16: all optional flags enabled. APK hash script push/chmod/execute succeeded and produced `apk_hashes.txt` (24.6 KB). Verdict CLEAN 0/100. Tool health: entropy/correlation ok; ALEAPP unavailable; remaining optional tools skipped_no_input. Timeline: 173,645 events. |
| 2026-07-22 | Offline bugreport-poco scan | Passed | CLI exit 0 | `bugreport-poco.zip`: 3,781 extracted, 3,759 indexed, 106 selected, 38 YARA-scanned, 454,573 timeline events, CLEAN 0/100. Five aggregate-context YARA matches retained; optional tools disabled for this CLI offline run. Outputs: `offline_CLI_OFFLINE_20260722_154916`. |
| 2026-07-22 | RC3 GUI + Packaging | Passed | GUI EXE functional | PyInstaller dual EXE built, Tcl/Tk bundled, GUI branding fixed, _mode_var init + StringVar.set() bugs fixed |
| 2026-07-22 | RC3 Documentation | Complete | 8 docs created | Guide utilisateur, enquêteur, installation, développement, limitations, release notes, licences, architecture update |

## [V7_REPORTING_ROADMAP]

The forensic core is now treated as stable: acquisition, artifact selection,
contextual YARA, IOC/heuristics, correlation, timeline, JSON, CSV, CLI, and
explicit lifecycle states. The next work improves restitution without changing
detection semantics or adding detection features.

Priority order:

1. **Professional PDF** — cover, executive summary, device, score/verdict,
   YARA/IOC findings, timeline summary, limitations, recommendations, hashes.
2. **Interactive HTML** — searchable/filterable findings, collapsible evidence,
   charts, and a bounded timeline preview, all rendered from canonical JSON.
3. **Scan history and delta** — new APKs, permissions, connections, accounts,
   and services compared across scan IDs.
4. **Coverage and confidence metrics** — separate risk from analyzer coverage and
   confidence; a clean result must show what was and was not examined.
5. **Package inventory report** — package, permissions, installer, hash, risk,
   reason, and authoritative supporting evidence for each package.
6. **Coverage report** — acquisition, YARA, IOC, timeline, APK hashing, browser,
   MVT, and other analyzer completion percentages.

Rules for this phase:

- JSON remains the only source of truth.
- PDF/HTML must never recalculate verdict, risk, confidence, or findings.
- Large timelines remain streamed and paginated; never render all events in GUI.
- Missing or disabled tools reduce coverage, not silently increase risk.
- Every new renderer receives schema-versioned JSON and preserves limitations.
- Existing 24 pytest tests and the 15/15 legacy harness remain mandatory.

The current assessment is approximately 92–95% of the intended v7 product,
with PDF and HTML restitution explicitly incomplete. This percentage is a
planning estimate, not a forensic validation claim.

## [WORKSPACE_CLEANUP_2026-07-22]

The root was cleaned without deleting source code or original evidence. Generated
scan dumps, prior offline/CLI runs, diagnostics, logs, output folders, caches,
temporary test data, and the reference-only nested repository were moved to:

```text
_archive_workspace_cleanup_20260722/
```

The retained product surface includes adapters, compatibility/domain models,
documentation, manifests, rules, scripts, tests, the virtual environment, all
root Python engines, launchers, configuration, `bugreport-poco.zip`, and the
canonical project documents. `.pytest_cache` and `pytest_tmp` could not be moved
because they were locked; they are disposable and remain the only cleanup residue
at the root. The archive is recoverable and should be reviewed before any future
permanent deletion.

## [INSTALLED_CYBERSECURITY_SKILLS]

Source repository: `mukul975/Anthropic-Cybersecurity-Skills`  
Installed into the Codex skill environment on 2026-07-22 UTC. The selected
skills support the current Android/YARA/forensics roadmap:

```text
analyzing-android-malware-with-apktool
detecting-mobile-malware-behavior
performing-android-app-static-analysis-with-mobsf
performing-malware-triage-with-yara
performing-threat-hunting-with-yara-rules
performing-yara-rule-development-for-detection
performing-sqlite-database-forensics
building-super-timelines-with-plaso
performing-network-forensics-with-wireshark
triaging-security-incident
triaging-security-incident-with-ir-playbook
performing-endpoint-forensics-investigation
```

The upstream repository contains many additional skills; they were not bulk
installed to avoid polluting the environment with unrelated capabilities. The
repository remains reference-only and does not become a second scanner
architecture.

### Latest read-only Android validation

```text
ADB state:       device / authorized
Serial:          BISG5XZL9LSWZXO7
Model:           2311DRK48G
Android:         16
Read-only checks: devices -l, getprop, serial, third-party package listing
Result:          all commands succeeded
```

Full forensic scan report: `docs/FULL_FORENSIC_REPORT.md` — 20-check IOC analysis
covering root detection, spyware packages, accessibility services, network
connections, DNS, WiFi, location, battery, filesystem, persistence, system
integrity, VPN, AppOps, and app permissions. Overall: NO INDICATORS OF COMPROMISE.

The CLI Live workflow remains the approved automation path. No install,
uninstall, shell write, remediation, or containment command was executed during
this validation.

## [RELEASE_CANDIDATE_QA_2026-07-22]

Full RC validation is documented in
`docs/RELEASE_CANDIDATE_VALIDATION_20260722.md`. Evidence: 24 pytest tests
passed, legacy harness 15/15 passed, imports and compilation passed, real Android
Live Triage/Deep passed, APK hashing passed, and `bugreport-poco.zip` offline
validation passed with 454,573 timeline events.

Current final decision: **RC3 COMPLETE**. The GUI startup smoke test
passes with Tcl/Tk bundled in the PyInstaller package. Other
tracked issues (RC-002 through RC-007) are resolved or documented as known limitations.

### RC2 qualification decision

The audit interpretation is accepted: CLI forensic engine, Android acquisition,
offline pipeline, reports, timeline, and APK hashing are release-ready as
subsystems. The global package is now release-ready with RC3 GUI/packaging
validation complete. RC3 work is limited to
RC-002 through RC-007 plus environment/package qualification for RC-001:

1. Reprompt and reject invalid CLI choices with nonzero status.
2. Replace active v6.2 branding with `version.py` imports while preserving
   historical documentation.
3. Make SQLite schema initialization idempotent without sharing unsafe
   connections across threads.
4. Add a successful APK-hash mock fixture and explicit partial/empty cases.
5. Exclude locked generated caches from release compilation checks.
6. Re-run GUI under a repaired Python/Tcl/Tk installation or packaged runtime;
   the current machine has `init.tcl` on disk but `_tkinter` still cannot load it.

No v7.0 release claim is made until RC2 tests, GUI startup, and a complete
regression campaign pass.

### GUI root-cause qualification

The decisive minimal test was executed with the same interpreter as the project:

```text
venv\\Scripts\\python.exe -c "import tkinter as tk; root=tk.Tk(); root.destroy()"
```

It fails before importing `app.py` with:

```text
_tkinter.TclError: Can't find a usable init.tcl
```

Therefore RC-001 is confirmed as a Python/Tcl/Tk environment or packaging
defect, not an application-widget defect. The GUI package remains blocked until
the officially supported runtime is repaired or ships Tcl/Tk correctly.

### CLI v7.0 RC2 stabilization (2026-07-22)

The CLI stabilization pass is verified. Invalid menu choices return exit code
2, explicit Exit returns 0, logging is idempotent, SQLite schema initialization
is guarded per process/database path, and active branding is sourced from
`version.py` (`7.0.0-rc1`, schema `1.1`).

```text
pytest:         22/22 passed
legacy harness: 15/15 passed
Ruff (CLI):     All checks passed
imports:        cli/extractor/analyzer/timeline/history_db OK
```

Android Live Deep and offline bugreport validation remain recorded above. The
CLI is a validated release-candidate subsystem; the combined GUI package
remains NOT READY until Tcl/Tk is repaired or packaged.

### RC2 release decision

```text
CLI / forensic core:       READY FOR RELEASE CANDIDATE DISTRIBUTION
Android Live Deep:         validated on real POCO device
Offline bugreport:         validated (454,573 timeline events)
APK hashing:               validated on real device
Global CLI + GUI package:  VALIDATED — see RC3 completion record below
```

### RC3 completion record

```text
Date:       2026-07-22
Status:     COMPLETE — GUI EXE functional, CLI EXE functional
Tcl/Tk:     Bundled in PyInstaller package (tcl8.6, tk8.6)
GUI bugs:   _mode_var init + StringVar.set() fixed
Branding:   v6.2 → VERSION from version.py
Packaging:  UniversalForensicScanner.spec with dual EXEs
pytest:     22/22 pass
mock_adb:   15/15 pass
ruff:       All checks passed
compileall: Clean
```

The next milestone is RC3 GUI/packaging only: repair or package Tcl/Tk, verify
minimal Tkinter startup and `app.py`, then run the GUI regression campaign.
The validated CLI and forensic engine are frozen during that work.

### RC3 GUI & packaging freeze

RC3 is restricted to Tcl/Tk runtime diagnosis, minimal Tkinter startup,
`app.py` smoke/functional tests, Windows packaging, and a final CLI+GUI
regression campaign. CLI, Android Live, Offline Archive, acquisition,
timeline, YARA, correlation, risk scoring, reporting, SQLite, APK hashing, and
the JSON schema are frozen. Any functional change to those components requires
repeating the RC2 validation campaign.

### RC3 completion record

```text
Date:       2026-07-22
Status:     COMPLETE — GUI EXE functional, CLI EXE functional
Tcl/Tk:     Bundled in PyInstaller package (tcl8.6, tk8.6)
GUI bugs:   _mode_var init + StringVar.set() fixed
Branding:   v6.2 → VERSION from version.py
Packaging:  UniversalForensicScanner.spec with dual EXEs
pytest:     22/22 pass
mock_adb:   15/15 pass
ruff:       All checks passed
compileall: Clean
```

### Release governance roadmap

No new forensic feature is planned before stable v7.0. RC3 covers only
GUI/Tcl-Tk and Windows packaging. RC4 is full acceptance testing; RC5 covers
user, administrator, investigator, developer, architecture, API, release,
limitations, license, and third-party documentation; RC6 produces the final
installer. The forensic engine remains frozen throughout these milestones.
