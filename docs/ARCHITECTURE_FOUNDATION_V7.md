# Architecture Foundation v7.0

Status: Phase 1 implementation plan and baseline assessment  
Authoritative product: repository root (v7.0-rc3)  
Reference-only code: `Forensic-Scanner-Multi-Plateforme/`

## 1. Current architecture assessment

The root application is a working, manifest-driven forensic scanner whose primary
entry point is `app.py`. Android acquisition is performed by `extractor.py` and
`adapters/android_adapter.py`; other platform acquisition is implemented in the
adapter package. `analyzer.py` is a monolithic compatibility pipeline that
coordinates local YARA/IOC analysis, risk scoring, history, external tools, and
optional network intelligence. `custody.py` packages and signs evidence after
analysis. `timeline.py` produces CSV dictionaries. `archive_engine.py` supports
offline archives. The GUI directly coordinates most of these modules.

The v7.0-rc3 pipeline is operational and is the release path. The v6.2
pipeline is preserved as a compatibility baseline. The existing `mock_adb.py` harness is the
regression gate.

### Current data flow (v7.0-rc3)

```text
GUI / CLI
  -> platform adapter or extractor
  -> dict[artifact_id, Path]
  -> monolithic analyzer and optional bridges
  -> mutable AnalysisResult
  -> JSON report / timeline / custody package / GUI
```

### Current strengths

- Manifest-driven Android acquisition with triage and deep profiles.
- Existing adapter abstraction and platform registry.
- Local dump analysis and an offline archive path.
- Structured logging in the main modules.
- Existing risk, history, timeline, and custody capabilities.
- A 15-scenario regression harness covering the current pipeline.

## 2. Coupling and risk inventory

| Area | Current coupling | Risk | v7 treatment |
|---|---|---|---|
| Acquisition | `extractor.py` returns paths and writes failure text as if it were evidence | Failed acquisitions can be confused with acquired evidence; command exit codes and exact times are lost | Canonical acquisition results and artifacts; separate logs/derived data |
| Android adapter | Executes ADB and creates local files but returns string paths | No uniform provenance or immediate immutable manifest | Wrap first; replace only after parity tests |
| Analyzer | Accepts path dictionaries, imports most bridges, performs history and risk work | Platform/tool coupling and broad failure surface | Compatibility converter first, then analyzer contracts/orchestrator |
| Tool bridges | Some bridges call ADB directly (`apkid`, MobSF, browser, PCAP) | Analysis can mutate or reacquire from a target | Split acquisition helpers from local analyzers in later phases |
| Evidence | `custody.py` hashes a directory after analysis and uses a local HMAC key | Derived and original files may be mixed; key provenance/identity is weak | Acquisition-time manifest, separated directories, chained ledger, explicit trust model |
| Timeline | Dictionary events and naive local timestamps | Ambiguous timezone and schema drift | Canonical UTC `Event`; legacy CSV adapter |
| Reporting | `AnalysisResult.to_dict()` is v6.2-specific | Multiple consumers can infer fields differently | Canonical schema-versioned `ScanResult` JSON |
| GUI | Coordinates acquisition, analysis, tools, reporting, containment, and subprocesses | Hard to test; UI failures affect workflow | Keep compatibility facade, move orchestration behind it incrementally |
| History/cache | SQLite writes occur inside analysis | Contention and analysis side effects | Serialized repository and hash identity in later phase |
| Time | `time.time()` and naive `datetime.now()` are common | Non-reproducible/ambiguous timestamps | New contracts require timezone-aware values normalized to UTC |
| Secrets | API integrations use environment inconsistently; custody key lives under `rules/` | Secret lifecycle and source-tree leakage risk | Validated config and OS/env secret providers in a later phase |
| Concurrency | One YARA pool exists; external tools are mostly sequential | No declared isolation, timeout, or group limits | Bounded execution groups after analyzer contracts exist |

No v7 claim of forensic soundness will be based on hashing alone. The target
controls also include command provenance, read-only behavior where available,
original/derived separation, UTC timing, limitations, serialized custody writes,
and verification.

## 3. Proposed directory structure

```text
domain/                 canonical immutable models and enums
contracts/              acquisition and analyzer protocols/results
compat/                 v6.2 <-> v7 converters and facades
acquisition/            platform acquisition implementations
analysis/               local-only analyzers and bounded orchestrator
evidence/               manifests, ledger, verification, serialized writer
reporting/              canonical JSON plus display-only HTML/PDF renderers
config/                 validated non-secret configuration
cache/                  content-addressed analyzer result cache
validation/             honest platform validation records and schemas
tests/                  v7 unit, contract, integrity, isolation, compatibility tests
docs/                   architecture and migration records
```

These packages are added beside the v6.2 modules. Existing imports remain valid
until each caller has migrated and passed parity tests.

## 4. Root-module migration map

| Current module | Decision | Destination / rationale |
|---|---|---|
| `core.py` | KEEP TEMPORARILY | Logging and ADB compatibility; split command runner later |
| `usb_monitor.py` | REIMPLEMENT | Probe service using acquisition contracts |
| `extractor.py` | MERGE | Android acquisition compatibility facade |
| `adapters/base_adapter.py` | REIMPLEMENT | Narrow `AcquisitionAdapter` protocol |
| `adapters/android_adapter.py` | MERGE | First reference acquisition adapter |
| `adapters/ios_adapter.py` | KEEP TEMPORARILY | Convert after Android validation |
| `adapters/linux_docker_adapter.py` | REIMPLEMENT | Separate SSH, Linux, and Docker adapters |
| `analyzer.py` | KEEP TEMPORARILY | Compatibility facade while analyzers migrate |
| `heuristics.py` | MERGE | Local analyzer/risk input after contract conversion |
| `mvt_bridge.py` | REIMPLEMENT | Local-input subprocess analyzer with dedicated limit |
| `aleapp_bridge.py` | REIMPLEMENT | Local-input subprocess/SQLite analyzer |
| `capa_bridge.py` | REIMPLEMENT | Local CPU/subprocess analyzer |
| `apkid_bridge.py` | REIMPLEMENT | Separate target acquisition from local APKiD analysis |
| `quark_bridge.py` | REIMPLEMENT | Local subprocess analyzer with dedicated limit |
| `intel_bridge.py` | REIMPLEMENT | Rate-limited API analyzer and cache |
| `mobsf_bridge.py` | REIMPLEMENT | APK acquisition separated from API analysis |
| `entropy_bridge.py` | MERGE | Local CPU analyzer |
| `browser_forensics_bridge.py` | REIMPLEMENT | Remove ADB calls; consume local database artifacts |
| `correlation_engine.py` | MERGE | Consume canonical findings/events |
| `archive_engine.py` | MERGE | Offline acquisition adapter with safe extraction |
| `pcap_bridge.py` | REIMPLEMENT | Capture acquisition separate from local parsing |
| `timeline.py` | REIMPLEMENT | Canonical Event production; CSV becomes renderer |
| `history_db.py` | MERGE | Serialized repository, cache, incremental identity |
| `custody.py` | KEEP TEMPORARILY | Preserve packaging; new evidence ledger introduced beside it |
| `remediation_engine.py` | KEEP TEMPORARILY | Explicit post-scan action, outside acquisition/analyzer contracts |
| `containment_engine.py` | KEEP TEMPORARILY | Explicit response path; never part of read-only acquisition |
| `scan_offline.py` | MERGE | Compatibility CLI over canonical orchestration |
| `app.py` | KEEP TEMPORARILY | GUI compatibility consumer; thin facade later |
| `mock_adb.py` | MERGE | Permanent regression/compatibility tests |

## 5. Nested reference repository inventory

The nested repository is not an independently maintained product.

| Nested area | Decision | Reason |
|---|---|---|
| `core/base_scanner.py` | ARCHIVE | Useful concepts, but random dictionary results conflict with canonical models |
| `core/scanner_registry.py` | ARCHIVE | Root registry/contracts will supersede it |
| `core/platform_detector.py` | MERGE | Reuse detection ideas only where root probing lacks coverage |
| `scanners/android_scanner.py` | DELETE AFTER VALIDATION | Root Android implementation is authoritative |
| `scanners/ios_scanner.py` | KEEP TEMPORARILY | Reference commands during later iOS migration |
| `scanners/windows_scanner.py` | MERGE | Source for the future root Windows acquisition adapter |
| `scanners/linux_scanner.py` | MERGE | Source for the future SSH/Linux acquisition adapter |
| `scanners/network_scanner.py` | ARCHIVE | Outside the initial platform acquisition migration |
| `scanners/cloud_scanner.py` | MERGE | Reference for future cloud adapters |
| `scanners/macos_scanner.py` | KEEP TEMPORARILY | Reference only; not a v7 initial target |
| `scanners/memory_scanner.py` | KEEP TEMPORARILY | Reference only; no duplicate architecture |
| `scanners/disk_scanner.py` | KEEP TEMPORARILY | Reference only; future offline acquisition source |
| `analyzers/` | ARCHIVE | Root analyzers are more capable; reuse isolated parsing only if proven |
| `collectors/` | ARCHIVE | Superseded by acquisition contracts |
| `reports/report_generator.py` | KEEP TEMPORARILY | Reference markup only; must render canonical JSON |
| `gui/` | DELETE AFTER VALIDATION | Root GUI is authoritative |
| nested rules | KEEP TEMPORARILY | Compare provenance/license/coverage before any merge |

After platform parity and validation, the nested tree should be moved to an
archive branch or removed from release packages. It must not be imported by root
runtime code.

## 6. Compatibility strategy

1. Add immutable v7 domain models without changing v6.2 call signatures.
2. Convert `dict[str, Path]` extraction outputs to canonical `Artifact` objects
   in `compat/`, without changing the files or legacy dictionary.
3. Convert legacy analysis results into canonical results for new consumers.
4. Preserve `run_extraction()`, `analyze()`, `save_report()`, and GUI behavior.
5. Add a v7 facade only after model tests and the 15-test harness pass.
6. Migrate Android behind the facade and compare artifact IDs/counts/hashes.
7. Remove legacy paths only after real-device validation and an explicit release.

Converters are deliberately one-way where lossless round trips cannot be
guaranteed. Conversion limitations must be recorded rather than invented.

## 7. Detailed phased implementation plan

### Phase 1: canonical contracts foundation (this change)

- Add enums and immutable `Artifact`, `Finding`, `Event`, `ScanContext`, and
  `ScanResult` models.
- Enforce required identifiers, local evidence paths, SHA-256 format, confidence
  and risk ranges, UTC-aware times, and artifact references.
- Add deterministic JSON-safe serialization and parsing.
- Add converters from v6.2 extraction dictionaries and `AnalysisResult`.
- Add focused unit tests. Do not change production scan flow.

### Phase 2: strict interfaces

- Add acquisition/analyzer protocols and structured result/error records.
- Add runtime contract tests and cancellation/timeout declarations.
- Wrap the existing Android extractor without rewriting it.

### Phase 3: Android acquisition and evidence

- Create the case directory layout.
- Capture every command, exit code, UTC start/end time, warning, and limitation.
- Hash immediately after acquisition, prevent overwrite, write an immutable
  manifest, and append through one serialized custody writer.
- Add full re-hash and ledger-chain verification.
- Compare legacy/v7 artifact counts and content hashes.

### Phase 4: local analyzer contracts

- Split direct target access from APKiD, browser, MobSF, and related bridges.
- Adapt local analyzers one at a time to `Artifact -> AnalyzerResult`.
- Preserve legacy risk results through a compatibility aggregation layer.

### Phase 5: bounded orchestration, cache, and incremental analysis

- Add declared execution groups and bounded executors/semaphores.
- Isolate failures/timeouts and validate analyzer output.
- Add content-addressed, analyzer-versioned cache entries.
- Analyze only new/changed artifact hashes while retaining prior provenance.

### Phase 6: canonical reporting and configuration

- Make schema-versioned `ScanResult` JSON the source of truth.
- Render HTML/PDF and GUI views without recomputing verdicts.
- Add validated configuration and external secret providers.

### Phase 7: platform-by-platform migration

- Convert iOS, Windows, SSH/Linux, Docker, and cloud independently.
- Require contract, parity, integrity, and real-target validation per adapter.

### Phase 8: release engineering

- Establish CI gates, benchmarks, validation records, documentation, and an
  installer only after platform validation is reproducible.
- Archive/retire the nested reference repository.

## 8. Test plan

- Baseline: run `venv\\Scripts\\python.exe mock_adb.py` after every phase.
- Models: validation, UTC normalization, immutability, JSON round trips, path and
  hash rejection, artifact-reference integrity.
- Contracts: adapters/analyzers satisfy protocols and declare execution policy.
- Integrity: manifest hash verification, missing/modified evidence, chain order,
  and original/derived separation.
- Isolation: timeout, crash, malformed output, SQLite serialization, API outage.
- Compatibility: v6.2 entry points, GUI import/scan path, scoring parity.
- Performance: record probe, acquisition, hashing, each analyzer, correlation,
  report generation, and total time before optimizing.
- Static gates: compileall, import smoke test, Ruff, and mypy on migrated modules.
- Real-platform tests use detailed validation records; partial results remain
  partial and never receive a simple pass checkmark.

## 9. Rollback strategy

- Phase 1 adds packages and tests only; legacy runtime imports none of them.
- If any regression appears, remove the new `domain/`, `compat/`, and Phase 1
  tests/docs without modifying v6.2 production modules.
- Later adapters remain behind feature flags/facades with v6.2 as the default
  until parity is demonstrated.
- Evidence formats are versioned and never migrated in place.
- Database changes use additive migrations and backups; no destructive migration
  is allowed during the compatibility period.
- Because the root directory currently has no Git metadata, filesystem rollback
  must use reviewed patch reversal or a user-created repository snapshot. Small,
  isolated changes are therefore mandatory.

## 10. Phase 1 limitations

- The canonical models do not make the existing acquisition path forensically
  sound by themselves.
- No custody ledger, immutable manifest writer, bounded orchestrator, cache,
  validated configuration, or renderer is implemented in Phase 1.
- Legacy timestamps remain naive/local until their producing modules migrate.
- The nested reference repository remains present but is not imported.
