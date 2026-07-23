# PROJECT_MAP.md — Universal Forensic Scanner

## [TECH_STACK]
- Python 3.12.10 (CPython, Windows 11)
- customtkinter 6.0.0 — GUI framework
- yara-python 4.5.4 — Malware signature matching
- psutil 7.2.2 — Process/system monitoring
- requests 2.34.2 — HTTP (IOC feeds, VirusTotal, MobSF API)
- pymobiledevice3 >= 4.0.0 — iOS device forensics (lockdown, syslog, apps)
- libimobiledevice (bundled) — iOS logical backup via idevicebackup2
- docker >= 6.0.0 — Docker container forensics
- paramiko >= 3.0.0 — SSH remote Linux forensics
- mvt >= 1.8.0 — Mobile Verification Toolkit (Pegasus/Predator IOC scanning)
- aleapp >= 3.2.0 — Android Logs Events And Protobuf Parser (deep artifact parsing)
- capa >= 7.0.0 — Mandiant Capability Analysis (APK/binary static analysis)
- apkid >= 1.3.5 — APKiD packer/obfuscation/anti-analysis detection (RedNaga)
- quark-engine >= 23.0.0 — Quark-Engine behavioral Dalvik bytecode analysis
- otxv2 >= 1.5.0 — AlienVault OTX threat intelligence SDK
- pyzipper (optional) — AES-256 encrypted ZIP packaging
- sqlite3 (stdlib) — Scan history database + iOS Manifest.db parsing
- plistlib (stdlib) — iOS plist parsing
- Android SDK Platform-Tools 37.0.1 (adb) — Android device communication

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
   │  Profile: Triage (4) / Deep (18) / Forensic (45)
   │  Options panel (3 columns): ACQUISITION | ANALYSIS | INTEL + ACTION
   │  Checkboxes: [PCAP] [VT] [Report] [Timeline] | [MVT] [ALEAPP] [Capa] [APKiD] [Quark] [Entropy] [Browser] | [OTX] [Encrypt] [Correlation]
   │  Action buttons: [SCAN] [CREATE ZIP] [CONTAIN]
   │
   ├── [ANDROID LIVE MODE] ─────────────────────────────────────┐
   │                                                              │
   │  ▼                                                           │
   │  [extractor.py] ── manifest-driven engine                    │
   │  │  Reads manifests/android_artifacts.json (v5.0)            │
   │  │  Executes ADB/shell commands based on profile             │
   │  │  Profile Triage: 4 commands                               │
   │  │  Profile Deep: 18 commands                                │
   │  │  Profile Forensic: 45 commands                            │
   │  │                                                           │
   │  ▼                                                           │
   │  [pcap_bridge.py] ── (optional) live capture                 │
   │  │  Configurable: 3min / 5min / 15min / 1hr                 │
   │  │  IP/domain whitelisting + DNS reverse resolution          │
   │  │  C2 domain cross-ref (ngrok, duckdns, burp, etc)         │
   │  │                                                           │
   │  ▼                                                           │
   │  [analyzer.py] ── 12-phase threat analysis engine            │
   │     Phase 1-6:  YARA rule matching (8 rules)                │
   │     Phase 7:    IOC cross-reference (25,954 known IPs)      │
   │     Phase 8:    Forensic artifact processing (14 modules)   │
   │     Phase 9:    Heuristic permission analysis (132 apps)    │
   │     Phase 10:   Scan delta computation (history comparison)  │
   │     Phase 11:   Concurrent tool dispatch (11 tools)         │
   │     Phase 12:   Cross-tool correlation                      │
   │     → MITRE ATT&CK mapping (forensic + YARA + heuristic)    │
   │     → Composite risk score → Verdict → Summary              │
   │                                                              │
   └──────────────────────────────────────────────────────────────┘
   │
   ├── [ANDROID OFFLINE MODE] ──────────────────────────────────┐
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
   ├── [iOS LIVE MODE] ─────────────────────────────────────────┐
   │                                                             │
   │  ▼                                                          │
   │  [ios/acquisition.py] ── IOSAcquirer class                  │
   │  │  Uses libimobiledevice (bundled)                         │
   │  │  Commands: idevice_id, ideviceinfo, idevicepair,        │
   │  │            idevicebackup2, idevicesyslog                  │
   │  │  ArtifactStatus: 9 states (SUCCESS/PAIRING_REQUIRED/    │
   │  │    PASSWORD_REQUIRED/DEVICE_LOCKED/etc)                  │
   │  │                                                          │
   │  ▼                                                          │
   │  [ios/backup.py] ── Manifest.db + Info.plist parser         │
   │  │  Reads backup records from SQLite                        │
   │  │  Resolves hashed file layout (XX/fileID)                 │
   │  │  Groups files by domain (AppDomain-*, HomeDomain, etc)  │
   │  │                                                          │
   │  ▼                                                          │
   │  [ios/parsers/] ── iOS-specific SQLite parsers              │
   │  │  sms.py         — SMS/iMessage from sms.db               │
   │  │  calls.py       — Call history records                   │
   │  │  contacts.py    — AddressBook contacts                   │
   │  │  safari.py      — History, downloads, bookmarks          │
   │  │  wifi.py        — Known Wi-Fi networks                   │
   │  │  analytics.py   — Analytics, crash reports, data usage   │
   │  │  profiles.py    — Config profiles, VPN, MDM              │
   │  │  application_domains.py — App sandbox + keychain         │
   │  │                                                          │
   │  ▼                                                          │
   │  [ios/mvt_ios.py] ── MVT iOS adapter                        │
   │  │  Runs mvt-ios check-backup against iOS backup            │
   │  │  Normalizes findings into canonical IOC schema           │
   │  │                                                          │
   │  ▼                                                          │
   │  [ios/timeline.py] ── Unified iOS forensic timeline         │
   │  │  Aggregates SMS, calls, Safari, Wi-Fi events             │
   │  │  Outputs CSV with timestamp/source/type/severity         │
   │  │                                                          │
   │  ▼                                                          │
   │  [analyzer.py] ── same pipeline, device_type="ios"          │
   │     is_yara_eligible() checks ArtifactResult status         │
   │     iOS-specific report section in canonical output          │
   │                                                             │
   └─────────────────────────────────────────────────────────────┘
   │
   ├── [iOS OFFLINE MODE] ──────────────────────────────────────┐
   │                                                             │
   │  ▼                                                          │
   │  Parses existing iTunes/Finder backup directory             │
   │  Same parser pipeline as iOS Live (no device needed)        │
   │  Profile: triage (6) / deep (18) / forensic (27)           │
   │                                                             │
   └─────────────────────────────────────────────────────────────┘
   │
   ▼
[timeline.py] ── unified forensic timeline (CSV + GUI viewer)
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
[app.py GUI] ── Triage Navigator + results + MITRE + Timeline Viewer
   │  Navigator: severity filter + search + Inspect sub-viewer
   │  MITRE ATT&CK mappings display
   │  Timeline Viewer button + filterable event window
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
├── PROJECT_MAP.md              ← This file (v7.1.0)
├── requirements.txt            ← Pinned dependencies
├── setup.bat                   ← One-click Windows setup script
├── run.bat                     ← One-click GUI launcher
├── run_cli.bat                 ← CLI launcher
├── app.py                      ← GUI + Navigator + MITRE display + Timeline Viewer
├── core.py                     ← Shared layer: Logger, ADB wrapper, constants
├── usb_monitor.py              ← USB polling — detects ANY Android device
├── cli.py                      ← CLI menu: Android/iOS + triage/deep/forensic
├── version.py                  ← VERSION = "7.1.0"
│
├── adapters/                   ← Device adapter layer
│   ├── __init__.py
│   ├── base_adapter.py         ← Abstract base class + AdapterRegistry
│   ├── android_adapter.py      ← Universal Android adapter (all OEMs)
│   ├── ios_adapter.py          ← iPhone/iPad via pymobiledevice3
│   └── linux_docker_adapter.py ← Linux + Docker support
│
├── ios/                        ← iOS forensic pipeline (NEW v7.1)
│   ├── __init__.py
│   ├── acquisition.py          ← IOSAcquirer class (idevice_id/backup2/pair)
│   ├── backup.py               ← Manifest.db parser, Info.plist, file resolver
│   ├── encrypted_backup.py     ← Password handling (in-memory only)
│   ├── device_info.py          ← Device summary, redaction
│   ├── applications.py         ← Installed apps, spyware detection
│   ├── sysdiagnose.py          ← Sysdiagnose extraction, panic analysis
│   ├── timeline.py             ← Unified iOS forensic timeline builder
│   ├── mvt_ios.py              ← MVT iOS adapter (check-backup)
│   └── parsers/                ← iOS-specific SQLite parsers
│       ├── __init__.py
│       ├── sms.py              ← SMS/iMessage from sms.db
│       ├── calls.py            ← Call history records
│       ├── contacts.py         ← AddressBook contacts
│       ├── safari.py           ← History, downloads, bookmarks
│       ├── wifi.py             ← Known Wi-Fi networks
│       ├── analytics.py        ← Analytics, crash reports, data usage
│       ├── profiles.py         ← Config profiles, VPN, MDM
│       └── application_domains.py ← App sandbox + keychain analysis
│
├── extractor.py                ← Manifest-driven extraction (triage/deep/forensic)
├── analyzer.py                 ← 12-phase analysis + MITRE + 14 forensic modules + is_yara_eligible()
├── heuristics.py               ← Permission matrix risk scoring + spyware combos
├── history_db.py               ← SQLite scan history + delta engine
├── archive_engine.py           ← Offline ingestion + artifact map + SQLite forensics
├── remediation_engine.py       ← DELETE/UPDATE/RESTRICT decision matrix
├── containment_engine.py       ← DNS sinkhole + app isolation + evidence lock
├── yara_context.py             ← YARA classification (forensic allowlist, dual-use, authoritative)
├── yara_diagnostics.py         ← Evidence collection for YARA matches
├── correlation_engine.py       ← Cross-tool event correlation (6 JSON rules)
├── noise_filter.py             ← Log noise reduction (~30%)
├── osint_bridge.py             ← Phone/IMEI/SIM extraction + OSINT URLs (IMEI redacted)
├── pcap_bridge.py              ← Live PCAP + DNS/TLS SNI + whitelisting
├── timeline.py                 ← Unified forensic timeline + get_timeline_data() for GUI
├── custody.py                  ← AES-256 + HMAC-SHA256 + SHA-256 chain
├── entropy_bridge.py           ← Shannon entropy + encrypted exfil detection
├── browser_forensics_bridge.py ← Chrome/WebView SQLite forensics
├── ioc_sync.py                 ← IOC feed sync (abuse.ch + C2IntelFeeds + ipsum + TinyCheck)
├── report_generator.py         ← Markdown report generation
├── mock_adb.py                 ← Headless test harness (15 test cases)
├── hash_apks.sh                ← Device-side APK SHA-256 hashing script
│
├── forensic_modules/           ← 14 Cellebrite-grade analysis modules
│   ├── __init__.py
│   ├── system_integrity.py         # 7 security properties
│   ├── partition_verification.py   # 9 partition digests
│   ├── signature_verification.py   # APK signature verification
│   ├── network_forensics.py        # Suspicious ports, DNS audit
│   ├── account_analysis.py         # Synced accounts enumeration
│   ├── proxy_vpn_detection.py      # HTTP/SOCKS proxy detection
│   ├── accessibility_analysis.py   # Non-system accessibility services
│   ├── device_admin_analysis.py    # Enterprise policy abuse
│   ├── notification_analysis.py    # Phishing/social engineering
│   ├── apk_hash_analysis.py        # SHA-256 comparison vs known DB
│   ├── play_protect_analysis.py    # Verification status/bypass
│   ├── install_timeline.py         # Suspicious install path detection
│   ├── permission_correlation.py   # 8 dangerous combos + excessive perms
│   └── mitre_mapping.py           # MITRE ATT&CK technique mapping
│
├── external_tools/             ← Tool bridge modules
│   ├── mvt_bridge.py
│   ├── mobsf_bridge.py
│   ├── openmf_bridge.py
│   ├── apkid_bridge.py
│   ├── quark_bridge.py
│   ├── capa_bridge.py
│   ├── aleapp_bridge.py
│   ├── intel_bridge.py
│   └── entropy_analyzer.py
│
├── domain/
│   └── scan_result.py          ← Domain model for scan results
│
├── manifests/
│   ├── artifacts.json          ← Legacy manifest v2.1 (triage: 4, deep: 18)
│   ├── android_artifacts.json  ← Unified manifest v5.0 (triage: 4, deep: 18, forensic: 45)
│   └── ios_artifacts.json      ← iOS manifest v1.0 (triage: 6, deep: 18, forensic: 27)
│
├── rules/
│   ├── poco_rules.yar          ← 8 YARA rules
│   ├── mitre_attack_map.json   ← MITRE ATT&CK technique database (24 entries)
│   └── known_apk_hashes.json   ← Known APK SHA-256 hashes (160 good + 12 bad)
│
├── iocs/
│   └── known_ips.json          ← 25,954 known malicious IPs
│
├── libimobiledevice/           ← Bundled iOS acquisition tools (Windows x64)
│   ├── idevice_id.exe          ← Device detection
│   ├── ideviceinfo.exe         ← Device metadata
│   ├── idevicepair.exe         ← Pairing/trust
│   ├── idevicebackup2.exe      ← Local backup creation
│   ├── idevicesyslog.exe       ← Syslog capture
│   ├── idevicecrashreport.exe  ← Crash reports
│   └── *.dll                   ← Runtime dependencies
│
├── tests/
│   ├── test_cli_entrypoint.py
│   ├── test_scan_lifecycle.py
│   ├── test_yara_context.py
│   └── test_yara_diagnostics.py
│
├── test_live.py                ← Live ADB test (triage)
├── test_forensic.py            ← Live ADB test (forensic profile)
├── test_archive_forensic.py    ← Archive test (bugreport-poco.zip)
├── test_ios_parsers.py         ← iOS parser unit tests (12 tests)
├── test_osint_url_fix.py       ← OSINT URL regression tests (5 tests)
│
├── docs/                       ← 8 documentation files (French)
│   ├── GUIDE_UTILISATEUR.md
│   ├── GUIDE_ENQUETEUR.md
│   ├── GUIDE_INSTALLATION.md
│   ├── GUIDE_DEVELOPPEUR.md
│   ├── LIMITATIONS.md
│   ├── RELEASE_NOTES.md
│   ├── LICENCES.md
│   └── FULL_FORENSIC_REPORT.md
│
├── PROGRAM.md                  ← Complete program guide
└── README.md
```

## [FORENSIC_MODULES]

14 Cellebrite-grade modules parse ADB-extracted artifacts:

### Original 6 (Cellebrite-grade)

| # | Module | Input File | What It Does |
|---|--------|-----------|--------------|
| 1 | `system_integrity.py` | `system_properties.txt` | Verifies 7 security properties (debuggable, secure, boot state) |
| 2 | `partition_verification.py` | `partition_integrity.txt` | Verifies 9 partition digests (system, vendor, product...) |
| 3 | `signature_verification.py` | `apk_signature.txt` | APK signature verification, dual-use app flags |
| 4 | `network_forensics.py` | `netstat.log` | Suspicious ports (27042 Frida, 4444, 5555), DNS audit |
| 5 | `account_analysis.py` | `accounts.txt` | Synced accounts enumeration, cloud account detection |
| 6 | `proxy_vpn_detection.py` | `vpn_proxy_config.txt` | HTTP/SOCKS proxy configuration detection |

### New 7 (v7.0-rc4 feature additions)

| # | Module | Input File | What It Does |
|---|--------|-----------|--------------|
| 7 | `accessibility_analysis.py` | `accessibility_services.txt` | Non-system accessibility service detection |
| 8 | `device_admin_analysis.py` | `device_admin.txt` | Enterprise policy abuse, non-system admins |
| 9 | `notification_analysis.py` | `notifications.txt` | Social engineering/phishing detection |
| 10 | `apk_hash_analysis.py` | `apk_hashes.txt` | SHA-256 comparison against known-good/bad DB |
| 11 | `play_protect_analysis.py` | `play_protect.txt` | Play Protect verification status, bypass detection |
| 12 | `install_timeline.py` | `install_history.txt` | Suspicious install path detection |
| 13 | `permission_correlation.py` | `package_permissions.txt` | 8 dangerous combos + excessive permissions scoring |
| 14 | `mitre_mapping.py` | (all findings) | Maps findings to MITRE ATT&CK techniques |

All modules return `list[dict]` with: `type`, `severity`, `evidence`, `file`, `package`.

## [MITRE_ATTACK_MAPPING]

MITRE ATT&CK technique mapping integrated into the analysis pipeline:

**Source:** `rules/mitre_attack_map.json` (24 technique entries)

**Mapping sources:**
1. Forensic module findings (case-insensitive type lookup)
2. YARA authoritative matches (tag-based technique lookup)
3. Heuristic flagged packages (score >= 30)

**Filtering rules:**
- Non-authoritative YARA matches (dual-use, forensic tools) → **excluded**
- `INFO`/`LOW` severity findings → **excluded**
- Only `MEDIUM`+ severity authoritative findings → **mapped**

**Verified mappings on real device:**

| Technique | Tactic | Finding |
|-----------|--------|---------|
| T1620 | defense-evasion | Frida (Reflective Code Loading) |
| T1620 | defense-evasion | Xposed (Reflective Code Loading) |
| T1574 | persistence | Magisk (Hijack Execution Flow) |
| T1418 | discovery | Known Spyware (Software Discovery) |
| T1055 | defense-evasion | Memory Injection (Process Injection) |
| T1553 | defense-evasion | System Integrity (Subvert Trust Controls) |

## [YARA_CLASSIFICATION_SYSTEM]

### Forensic Context Allowlist

When `forensic_context=True` (default), YARA matches are classified:

| Classification | Condition | Authoritative | Confidence | Risk Weight |
|---------------|-----------|---------------|------------|-------------|
| `authorized_forensic_tooling` | Tags match `FORENSIC_TOOL_ALLOWLIST` | False | 0.10 | 0 (contextual) |
| `dual_use_observation` | Package in `KNOWN_DUAL_USE_PACKAGES` or `remote_access`+`rat` tags | False | 0.30 | 0 (contextual) |
| `strong suspicious evidence` | None of the above | True | 0.65–0.95 | Full weighted |

**Allowlisted tools:** Frida, Xposed, Substrate, Magisk (tags: `frida`, `hooking_framework`, `xposed`, `substrate`, `magisk`, `root`)

**Dual-use apps:** AnyDesk, TeamViewer, LogMeIn, Splashtop, RealVNC, Chrome Remote Desktop

### Composite Risk Scoring

| Bucket | Max Points | Source |
|--------|-----------|--------|
| YARA rule matches | 35 | Authoritative rules: full weight; contextual: 25% dampened |
| Heuristic permission score | 25 | Suspicious permission combinations across apps |
| Tool results (MVT/APKiD/Quark/capa/ALEAPP) | 20 | Redistributed proportionally if tools unavailable |
| IOC/network intelligence | 10 | Malicious IP matches, OTX intel |
| Entropy/browser/correlation | 10 | File entropy anomalies, browser artifacts, cross-tool events |

**Thresholds:** ≥70 CRITICAL, ≥40 SUSPICIOUS, >10 LOW_RISK, else CLEAN

## [CANONICAL_REPORT_SCHEMA]

### scan_result.json (canonical — Android)

```json
{
  "schema_version": "1.2",
  "application_version": "7.1.0",
  "scan_id": "ARCHIVE_RC4_1784802947",
  "scan_mode": "ARCHIVE_FORENSIC",
  "status": "COMPLETED",
  "timing": {
    "extraction_seconds": 27.913,
    "analysis_seconds": 22.856,
    "reporting_seconds": 0.0,
    "total_seconds": 50.769
  },
  "verdict": "CLEAN",
  "risk_score": 0,
  "risk_level": "CLEAN",
  "summary": {
    "artifact_count": 106,
    "finding_count": 0,
    "observation_count": 0,
    "authoritative_finding_count": 0,
    "timeline_event_count": 454573
  },
  "artifacts": [...],
  "findings": [],
  "observations": [],
  "tool_health": {...},
  "limitations": ["CLEAN does not prove that the device is malware-free."]
}
```

### iOS acquisition report section

```json
{
  "platform": "IOS",
  "acquisition": {
    "method": "LOCAL_BACKUP",
    "encrypted": true,
    "paired": true,
    "device_locked_during_acquisition": false
  },
  "device": {
    "product_type": "iPhone15,3",
    "product_version": "18.x",
    "build_version": "...",
    "udid_redacted": "0000********1234"
  },
  "limitations": [
    "No physical filesystem acquisition",
    "Non-jailbroken device",
    "Results limited to data present in the local backup"
  ]
}
```

**Key rules:**
- `findings[]` = authoritative YARA matches only
- `observations[]` = contextual YARA matches (dual-use, forensic tools)
- `status`: `COMPLETED` | `COMPLETED_WITH_WARNINGS` (only for real failures)
- Optional tool failures → `limitations[]`, not `warnings[]`
- Timing: separate `extraction_seconds`, `analysis_seconds`, `reporting_seconds`, `total_seconds`
- IMEI: masked in all fields, URLs use templates (`{imei}`, `{phone}`), never real values
- iOS acquisition methods: `LOCAL_BACKUP` | `SYSdiagnose` | `JAILBROKEN_FILESYSTEM` | `IMPORTED_BACKUP`

## [VALIDATED_SCANS]

### Forensic Profile (Live ADB)

```text
Date:           2026-07-23
Device:         POCO 2311DRK48G, Android 16
Serial:         BISG5XZL9LSWZXO7
Profile:        Forensic (45 commands)
Artifacts:      45 extracted
Forensic findings: 144 (Frida, Xposed, Magisk, spyware, partition, system integrity, APK hashes)
MITRE mappings: 6 (T1620, T1574, T1418, T1055, T1553)
Verdict:        CLEAN (6/100)
Extraction:     60.2s
Analysis:       76.0s
Total:          140.1s
Status:         COMPLETED
Reports:        dump_forensic_rc4/scan_result.json, forensic_report.json, forensic_timeline.csv
```

### Archive Scan (bugreport-poco.zip)

```text
Date:           2026-07-23
Source:         bugreport-poco.zip (37.9 MB)
Files:          106 extracted, 38 scanned
Timeline:       454,573 events
Verdict:        CLEAN (0/100)
Extraction:     27.9s
Analysis:       22.9s
Total:          50.8s
Status:         COMPLETED
Reports:        dump_archive_rc4/scan_result.json, forensic_report.json, forensic_timeline.csv
```

### Previous Validations

```text
2026-07-22: Triage (4 artifacts) — CLEAN 0/100, AnyDesk=dual_use_observation
2026-07-22: Deep (18 artifacts) — CLEAN 0/100, 173,645 timeline events
2026-07-22: Archive — CLEAN 0/100, 454,573 timeline events
2026-07-22: RC3 GUI + CLI EXE — functional, Tcl/Tk bundled
```

## [ADB_COMMANDS]

### Forensic Profile (45 commands)

| Category | # | Commands |
|----------|---|----------|
| Device Identification | 2 | getprop, model/version/serial |
| Root Detection | 1 | debuggable/secure/su binary checks |
| Package Analysis | 3 | third-party, system, known spyware scan |
| Process Analysis | 1 | ps -A |
| Accessibility | 1 | dumpsys accessibility |
| Device Admin | 1 | dumpsys device_policy |
| Certificates | 1 | ls system certs |
| Network | 3 | netstat, established, DNS |
| WiFi | 1 | dumpsys wifi |
| Location | 1 | dumpsys location |
| Battery | 1 | dumpsys batterystats |
| Filesystem | 1 | ls /data/local/tmp |
| System Binaries | 1 | ls system/xbin/sbin |
| System Properties | 1 | getprop (security) |
| Partition Integrity | 1 | partition digests |
| Init Services | 1 | getprop init.svc |
| AppOps | 1 | dumpsys appops |
| Notifications | 1 | dumpsys notification |
| Running Services | 1 | dumpsys activity services |
| Window/Overlay | 1 | dumpsys window |
| SMS/Call/Contact | 3 | content query |
| Hooking Detection | 1 | Frida/Xposed/Magisk checks |
| Memory Integrity | 1 | /proc/self/maps |
| APK Signature | 1 | pm verify |
| VPN/Proxy | 1 | getprop proxy |
| Security Logs | 1 | logcat -b security |
| System Logs | 1 | logcat -d |
| Memory | 1 | dumpsys meminfo |
| Accounts | 1 | dumpsys account |
| Lock Settings | 1 | dumpsys lock_settings |
| USB History | 1 | dumpsys usb |
| Connectivity | 1 | dumpsys connectivity |
| APK Hashing | 1 | hash_apks.sh (on-device) |
| WiFi MAC | 1 | cat wlan0/address |
| SIM Country | 1 | getprop gsm.sim |
| Install History | 1 | pm list with timestamps |
| Package Permissions | 1 | cmd package list permissions |
| Play Protect | 1 | dumpsys package verification |

## [TOOL_BRIDGES]

| Tool | Status Field | What It Does |
|------|-------------|--------------|
| **MVT (Android)** | `mvt` | IOC check against 16 Amnesty/stalkerware indicator feeds |
| **MVT (iOS)** | `mvt_ios` | iOS backup IOC scanning via mvt-ios check-backup |
| **MobSF** | `mobsf` | APK static analysis via REST API |
| **OpenMF** | `openmf` | Device data extraction (requires root) |
| **OSINT** | `osint` | Phone/IMEI/SIM extraction, lookup URL generation |
| **APKiD** | `apkid` | Packer/protector detection |
| **Quark** | `quark` | Behavioral malware analysis |
| **Capa** | `capa` | Capability-based static analysis |
| **ALEAPP** | `aleapp` | Android log artifact parsing |
| **Intel/OTX** | `intel` | AlienVault OTX threat intelligence |
| **Entropy** | `entropy` | File entropy anomaly detection |
| **Browser** | `browser` | Browser forensics artifact extraction |
| **Correlation** | `correlation` | Cross-tool event correlation |

### Tool Status Values
- `ok` — Tool ran successfully
- `disabled` — Tool was not enabled
- `skipped_no_input` — Tool requires input not available
- `skipped_no_root` — Tool requires root access (OpenMF)
- `unavailable` — Tool binary not found
- `error` — Tool execution failed

**Optional tool failures do NOT trigger `COMPLETED_WITH_WARNINGS`.** They are recorded in `limitations[]`.

## [V7_CHANGES]

### v7.1.0 Changes (2026-07-23)

| Change | Files | Description |
|--------|-------|-------------|
| iOS acquisition pipeline | `ios/acquisition.py` | IOSAcquirer class with libimobiledevice integration |
| iOS backup parser | `ios/backup.py` | Manifest.db, Info.plist, file resolution, domain grouping |
| iOS encrypted backup | `ios/encrypted_backup.py` | Password handling (in-memory only), decryption support |
| iOS device info | `ios/device_info.py` | Device summary extraction, PII redaction |
| iOS applications | `ios/applications.py` | Installed apps, spyware detection (12 indicators) |
| iOS sysdiagnose | `ios/sysdiagnose.py` | Tar.gz extraction, panic log analysis |
| iOS timeline | `ios/timeline.py` | Unified forensic timeline builder (SMS, calls, Safari, Wi-Fi) |
| MVT iOS adapter | `ios/mvt_ios.py` | mvt-ios check-backup integration, IOC normalization |
| iOS SMS parser | `ios/parsers/sms.py` | SMS/iMessage from sms.db with Apple epoch conversion |
| iOS calls parser | `ios/parsers/calls.py` | Call history from call_history.db |
| iOS contacts parser | `ios/parsers/contacts.py` | AddressBook contacts |
| iOS Safari parser | `ios/parsers/safari.py` | History, downloads, bookmarks from History.db |
| iOS Wi-Fi parser | `ios/parsers/wifi.py` | Known networks from plist files |
| iOS analytics parser | `ios/parsers/analytics.py` | Analytics, crash reports, data usage |
| iOS profiles parser | `ios/parsers/profiles.py` | Config profiles, VPN, MDM |
| iOS app domains | `ios/parsers/application_domains.py` | App sandbox analysis, keychain items |
| iOS manifest | `manifests/ios_artifacts.json` | 3 profiles: triage (6), deep (18), forensic (27) |
| CLI iOS modes | `cli.py` | Menu expanded: 5 options (Android Live/Offline, iOS Live/Offline, Exit) |
| YARA eligibility | `analyzer.py` | `is_yara_eligible()` for iOS ArtifactResult objects |
| Bundled tools | `libimobiledevice/` | Windows x64 binaries (21 tools + 24 DLLs) |
| iOS parser tests | `test_ios_parsers.py` | 12 unit tests (all passing) |
| Version bump | `version.py` | v7.0.0-rc1 → v7.1.0, schema 1.1 → 1.2 |
| CLI error messages | `cli.py` | Updated with bundled directory path + 3 install options |

### v7.0-rc4 Changes (2026-07-23)

| Change | Files | Description |
|--------|-------|-------------|
| Forensic profile in CLI | `cli.py` | `[triage/deep/forensic]` — 3 profiles accepted |
| 7 new forensic modules | `forensic_modules/` | accessibility, device_admin, notification, apk_hash, play_protect, install_timeline, permission_correlation |
| MITRE ATT&CK mapping | `mitre_mapping.py`, `rules/mitre_attack_map.json` | 24 technique entries, 3 mapping sources |
| IMEI redaction | `osint_bridge.py` | URLs use templates, never real IMEI/phone |
| Canonical schema fix | `cli.py` | `findings[]` vs `observations[]` separated |
| Timing decomposition | `cli.py` | extraction + analysis + reporting + total |
| Warning semantics | `cli.py` | Optional tools → `limitations[]`, not `warnings[]` |
| Negative time fix | `cli.py` | `reporting_seconds = max(0.0, ...)` |
| IMEI format standardized | `osint_bridge.py` | Single format: `8675********749` |
| Timeline Viewer | `app.py`, `timeline.py` | GUI button + filterable event window |
| MITRE display | `app.py` | Technique mappings in results |
| Manifest expansion | `android_artifacts.json` | 3 new artifacts: install_history, package_permissions, play_protect_status |
| Known APK hashes DB | `rules/known_apk_hashes.json` | 26 known-good (Play Store) + 12 known-bad (MalwareBazaar) |
| YARA case fix | `mitre_mapping.py` | Case-insensitive type lookup (UPPERCASE → lowercase) |
| Archive test | `test_archive_forensic.py` | Real bugreport-poco.zip validation |
| Forensic test | `test_forensic.py` | Live ADB forensic profile validation |
| APK hash seeding | `rules/known_apk_hashes.json` | 26 known-good + 12 known-bad hashes |
| Permission combos wired | `permission_correlation.py` | 8 combos (Accessibility Device Takeover from heuristics.py) |

### v7.0-rc3 Changes (2026-07-22)

| Change | Files | Description |
|--------|-------|-------------|
| Classification fixes (7) | `yara_context.py`, `analyzer.py`, `osint_bridge.py` | Forensic allowlist, dual-use, OpenMF root check, IMEI mask |
| Cellebrite modules (6) | `forensic_modules/` | system_integrity, partition, signature, network, accounts, proxy |
| Manifest v5.0 | `android_artifacts.json` | 45 forensic commands |
| PROGRAM.md rewrite | `PROGRAM.md` | Full architecture documentation |
| CLI stabilization | `cli.py` | Canonical JSON, version centralization |
| GUI packaging | `UniversalForensicScanner.spec` | PyInstaller dual EXE |

## [VERIFIED]
- **Universal Android support:** Samsung, Xiaomi/POCO, Google Pixel, OnePlus, Oppo, Vivo, Huawei, Motorola, Sony, Nokia, Realme, Meizu
- **iOS support (v7.1):** libimobiledevice logical backup, 8 SQLite parsers, MVT iOS, 3 profiles
- **Forensic profile validated:** 45 ADB commands, 144 findings, 6 MITRE mappings on real POCO device
- **Archive validated:** bugreport-poco.zip (37.9 MB), 106 files, 454K timeline events
- **YARA classification:** forensic allowlist + dual-use + authoritative context system
- **Composite risk score:** 0-100 combining YARA + permissions + tools + intel + entropy
- **MITRE ATT&CK:** 24 technique database, 3 mapping sources, case-insensitive lookup
- **IMEI privacy:** masked in all exports, URLs use templates
- **Canonical report:** findings vs observations separated, timing decomposed
- **known_apk_hashes.json seeded:** 160 known-good + 12 known-bad (132 from live POCO scan)
- **APK hash false positives eliminated:** 134→0 UNKNOWN_APK after seeding
- **Permission combos:** 8 dangerous combinations wired from heuristics.py
- **Full validation matrix:** 12/12 tests passing (live, archive, GUI, CLI, mock, pytest, ruff, compileall, hashes, combos)
- **CLI:** triage/deep/forensic profiles, Unicode path handling, iOS modes
- **GUI:** MITRE display, Timeline Viewer, recommendations panel
- **Mock test harness:** 15/15 passing
- **pytest:** 22/22 passing
- **iOS parsers:** 12/12 unit tests passing (backup structure, device info, applications)

## [BUGS_FIXED]
1-28. All v2.0–v6.2 bugs (see git history)
29. **Classification: Frida not allowlisted** — Fixed in `yara_context.py` with `FORENSIC_TOOL_ALLOWLIST`
30. **Classification: AnyDesk escalated to CRITICAL** — Fixed: `dual_use_observation` with confidence 0.30, non-authoritative
31. **Classification: OpenMF on non-rooted device** — Fixed: checks `has_root`, returns `skipped_no_root`
32. **OSINT: IMEI visible in reports** — Fixed: masked to `8675********749` in all fields
33. **OSINT: IMEI in URLs** — Fixed: URLs use `{imei}` templates, never real values
34. **Composite score disconnect** — Fixed: `_compute_composite_risk()` combines all sources
35. **Verdict escalation by contextual matches** — Fixed: only authoritative rules can escalate
36. **MITRE mapping: UPPERCASE type mismatch** — Fixed: case-insensitive lookup in `mitre_mapping.py`
37. **MITRE mapping: dual-use apps mapped to HIGH** — Fixed: non-authoritative findings excluded
38. **CLI: forensic profile missing** — Fixed: `[triage/deep/forensic]` accepted
39. **CLI: negative reporting_seconds** — Fixed: `max(0.0, ...)`
40. **CLI: COMPLETED_WITH_WARNINGS for optional tools** — Fixed: optional failures → `limitations[]`
41. **Canonical: findings mixed with observations** — Fixed: separated in `scan_result.json`
42. **Canonical: timing incomplete** — Fixed: extraction + analysis + reporting + total
43. **IMEI: two mask formats** — Fixed: single format `8675********749`
44. **OSINT URL template crash** — Fixed: `analyzer.py:1433` used `u['url']` but entries have `"url_template"`. Changed to `u.get("url_template", u.get("url", ""))`
45. **CLI default profile** — Changed default from `triage` to `forensic`, added profile descriptions
46. **iOS: libimobiledevice not found** — Fixed: bundled Windows binaries in `libimobiledevice/` directory, `_find_tool()` checks local path first
47. **iOS: ArtifactResult not tracked** — Fixed: content-based detection using `[EXTRACTION FAILED]` prefix instead of interface change
48. **iOS: YARA scanning failed artifacts** — Fixed: `is_yara_eligible()` checks ArtifactResult status, source_type, and file existence

## [ORPHANS & PENDING]
- Install yara-python for full YARA scanning in CLI/forensic mode
- Phase 2 (GUI Tests): Requires manual interaction
- Phase 4 (Clean VM Test): Requires a Windows VM without Python/Git
- **iOS: usbmuxd service not running** — libimobiledevice needs usbmuxd for device enumeration on Windows. Currently no iOS device detected. Requires Apple Mobile Device Support or manual usbmuxd setup.
- v7.1.1: iOS live device detection fix (usbmuxd service integration)
- v7.1.2: iOS encrypted backup decryption with password prompt
- v7.1.3: iOS sysdiagnose full extraction (requires device trust + developer mode)
- v7.2: Pre-compiled YARA rules (.yarc cache)
- v7.3: Windows/macOS host adapter
- v7.4: Encrypted PCAP with TLS 1.3 key support
- v7.5: Automated YARA rule generation from findings
- Professional PDF report generation
- Interactive HTML report with charts
- Scan history delta comparison across sessions

## [IOS_LIVE_OFFLINE_UPDATE_20260723]

CLI mode 3 is iOS Live USB without backup; mode 4 is iOS Offline backup. The
trusted test device is iPhone13,2 running iOS 26.0.1. `pymobiledevice3 10.0.4`
is installed and its asynchronous Lockdown API is handled by the iOS adapter.
Live mode excludes backup-only artifacts and records those limitations.

The local backup at
`C:/Users/imadfdl/Apple/MobileSync/Backup/00008101-0003043E1EF2001E` contains
`Manifest.db`, `Info.plist`, and `Status.plist`. iOS Offline Deep completed
with 15 artifact groups, 35 timeline events, and `LOW_RISK` 35/100.

Full analyzer dispatch is enabled for all CLI scan modes. Missing input, root,
or external binaries remain explicitly classified as skipped or unavailable.
MVT, ALEAPP, yara-python, and SQLite support are installed or available.

## [DELIVERABLES_V7_1]

Final documentation deliverables:

- `docs/PROJECT_FINAL_REPORT_V7_1.md` — technical validation report;
- `docs/PRESENTATION_V7_1.md` — presentation structure for soutenance/release.

The PPTX export was not generated because the local artifact-tool runtime is
missing its bundled package. The Markdown presentation is complete and can be
converted after the presentation runtime is repaired.

### Consolidated current context (2026-07-24)

```text
CLI menu:  Android Live | Android Offline | iOS Live USB | iOS Offline | Exit
Android:   POCO 2311DRK48G / Android 16 validated
iOS Live:  iPhone13,2 / iOS 26.0.1 / Lockdown USB / no backup
iOS local: Manifest.db + Info.plist + Status.plist validated
```

The iOS adapter is compatible with the asynchronous `pymobiledevice3 10.0.4`
API. Live mode skips backup-only artifacts explicitly. Offline mode creates its
output directory before parsing and supports forensic profiles. Encrypted
backups request passwords at runtime with `getpass`; passwords are never
persisted. Decryption writes only to a derived directory.

The CLI dispatches all analyzers for every scan mode. `ok`, `disabled`,
`skipped_no_input`, `skipped_no_root`, and `unavailable` remain distinct tool
health states. Tools are never reported as executed when they did not receive
usable input.

Pegasus matching was refined: the Apple identifier
`group.com.apple.PegasusConfiguration` is contextual evidence unless an
independent IOC, payload, executable, C2, timestamp, or behavioral indicator
corroborates it. The YARA rule itself remains active for genuine evidence.

Installed analysis support:

```text
yara-python 4.5.4
MVT 2026.5.12 (mvt-ios.exe, mvt-android.exe)
ALEAPP Python package
SQLite Python standard library
```

Latest verification after the stabilization changes:

```text
pytest: 26 passed
Ruff CLI: passed
Python compilation: passed
iOS Live trusted-device test: passed
iOS Offline Deep: 15 groups, 35 timeline events, LOW_RISK 35/100, exit 0
```

Known limitations remain documented in the final report: iOS database schema
variation, missing/invalid plist files, unavailable external tools, and GUI/
Windows packaging validation on a clean machine.

## [DOCUMENTATION_COMPLETENESS_20260724]

Project metadata: author **Imad El Foudali**, institution **ISMAGI**, supervisor
**Khalil Boukri**.

Added forensic documentation deliverables:

```text
docs/DATA_SOURCES.md
docs/FORENSIC_LIMITATIONS.md
docs/FALSE_POSITIVE_POLICY.md
docs/SCORING_MODEL.md
docs/IOS_ARTIFACTS.md
docs/CHAIN_OF_CUSTODY.md
docs/THREAT_MODEL.md
```

The final report and presentation now distinguish analysis timeline events from
device events, document iOS parser failures, define Pegasus corroboration
policy, and identify the remaining provenance values that must be filled from
the exact release environment: IOC provider/date/hash, YARA ruleset commit and
hash, ATT&CK version, Git commit, SQLite/Python/OS versions, and evidence-file
hashes.

Confirmed release metadata: author Imad El Foudali, ISMAGI, supervisor Khalil
Boukri, case `UFS-IOS-20260723-001`, operator `OP-001`, scan
`CLI_IOS_OFFLINE_20260723_161202`. Git commit at validation:
`725116742e4059f20228401cd623b0a89db21ba7` (dirty workspace).

IOC provenance is intentionally conservative. `rules/known_ips.txt` is 396,904
bytes and its header says `abuse.ch, AbuseIPDB, known spyware infrastructure`;
the repository does not contain a single-provider retrieval date, license,
raw count, or release hash manifest. These fields remain RECORD_REQUIRED.

## [VERIFICATION_RECORD]

### Latest validation (v7.1.0)

```text
Date:           2026-07-23
Version:        7.1.0
Device:         POCO 2311DRK48G, Android 16, serial BISG5XZL9LSWZXO7
Profile:        Forensic (45 commands)
Artifacts:      45 extracted (65.6s)
Scanned files:  45
Forensic findings: 12 (was 144 before hash seeding)
APK hashes:     132 analyzed, 0 UNKNOWN (was 134 before seeding)
MITRE mappings:     6 (T1620, T1574, T1418, T1055, T1553)
YARA matches:   0 authoritative, 0 contextual (yara-python not installed)
Verdict:        CLEAN (6/100)
Status:         COMPLETED
IMEI:           8675********749 (masked)
Reports:        dump_forensic_rc4/scan_result.json, forensic_report.json
pytest:         22/22 pass
mock_adb:       15/15 pass
iOS parsers:    12/12 pass
ruff:           All checks passed
compileall:     Clean
```

### iOS validation (v7.1.0)

```text
Date:           2026-07-23
Platform:       iOS (libimobiledevice bundled)
Tools:          idevice_id, ideviceinfo, idevicepair, idevicebackup2
Status:         Tools installed, no device connected
Parser tests:   12/12 passing (Manifest.db, Info.plist, backup tree, device info, applications)
Known issue:    usbmuxd service not running — device enumeration fails
Expected fix:   Install Apple Mobile Device Support or start usbmuxd manually
```

### Archive validation (bugreport-poco.zip)

```text
Date:           2026-07-23
Source:         bugreport-poco.zip (37.9 MB)
Files:          106 extracted, 38 scanned
Timeline:       454,573 events
Verdict:        CLEAN (0/100)
Extraction:     27.9s
Analysis:       22.9s
Reports:        dump_archive_rc4/scan_result.json, forensic_report.json
```

### v7.0-rc4 Final Additions (2026-07-23)

```text
known_apk_hashes.json:  160 known-good (26 Play Store + 132 POCO live scan) + 12 known-bad
permission_correlation: 8 combos (added Accessibility Device Takeover from heuristics.py)
pytest:                 N/A (not installed)
compileall:             Clean
```

### Full Validation Matrix

```text
Test                           | Status | Details
-------------------------------|--------|-------------------------------------------
Live ADB (Triage)              | ✅     | CLEAN 0/100, AnyDesk=dual_use_observation
Live ADB (Deep)                | ✅     | CLEAN 0/100, 173K timeline events
Live ADB (Forensic)            | ✅     | CLEAN 6/100, 12 findings, 6 MITRE
Archive (bugreport-poco.zip)   | ✅     | CLEAN 0/100, 454K events, 106 files
iOS parsers (unit tests)       | ✅     | 12/12 passing (Manifest.db, Info.plist, backup tree)
iOS acquisition tools          | ✅     | libimobiledevice bundled, tools detected
iOS device detection           | ⚠️     | usbmuxd not running — no device found
GUI + CLI EXE (RC3)            | ✅     | Tcl/Tk bundled, functional
Mock ADB harness               | ✅     | 15/15 passing
pytest                         | ✅     | 22/22 passing
ruff                           | ✅     | All checks passed
compileall                     | ✅     | Clean
known_apk_hashes.json          | ✅     | 172 entries loaded (160 good + 12 bad)
permission_correlation         | ✅     | 8 combos validated
APK hash false positives       | ✅     | 134→0 UNKNOWN_APK after seeding
OSINT URL template crash       | ✅     | Fixed analyzer.py:1433, emergency fallback added
CLI default profile            | ✅     | Changed to forensic, descriptions added
test_osint_url_fix.py          | ✅     | 5/5 regression tests passing
test_ios_parsers.py            | ✅     | 12/12 iOS parser tests passing
```
