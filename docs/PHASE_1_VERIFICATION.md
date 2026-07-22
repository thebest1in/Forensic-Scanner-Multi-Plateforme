# Architecture Foundation v7.0 — Phase 1 Verification

Date: 2026-07-22  
Scope: canonical domain models and v6.2 compatibility converters only

## Commands and observed results

```powershell
venv\Scripts\python.exe -m pytest -q
```

```text
......... [100%]
9 passed in 0.13s
```

```powershell
venv\Scripts\ruff.exe check domain compat tests
```

```text
All checks passed!
```

```powershell
venv\Scripts\mypy.exe domain compat
```

```text
Success: no issues found in 10 source files
```

```powershell
venv\Scripts\python.exe mock_adb.py
```

```text
[PASS] test_clean_device: CLEAN
[PASS] test_suspicious_device: CRITICAL | matches=4
[PASS] test_critical_device: CRITICAL | matches=6
[PASS] test_triage_profile: 4 files
[PASS] test_deep_profile: 18 files
[PASS] test_offline_clean: CLEAN | files=7
[PASS] test_offline_suspicious: CRITICAL | matches=3
[PASS] test_heuristics_clean: score=0 level=CLEAN
[PASS] test_heuristics_suspicious: score=100 level=CRITICAL
[PASS] test_pcap_clean: dns=2 c2=0
[PASS] test_pcap_c2_detected: c2=2
[PASS] test_custody_signing: valid=True tamper_detected=True
[PASS] test_remediation_suspicious: actions=5 delete=3 restrict=2
[PASS] test_remediation_clean: actions=0
[PASS] test_artifact_map: 5 artifacts
=== 15/15 tests passed ===
```

```powershell
venv\Scripts\python.exe -m compileall -q \
  -x 'venv|Forensic-Scanner-Multi-Plateforme|offline_SCAN|offline_scan|dump_forensic|offline_mock|offline_artifact_map_test' .
```

Result: exit code 0, no compiler output.

```powershell
venv\Scripts\python.exe -c "import app, analyzer, archive_engine, containment_engine, custody; from domain import Artifact, Finding, Event, ScanContext, ScanResult; from compat import legacy_extraction_to_artifacts, legacy_analysis_to_scan_result; print('legacy and v7 imports OK')"
```

```text
legacy and v7 imports OK
```

Tool versions used:

- pytest 9.1.1
- Ruff 0.15.22
- mypy 2.3.0

## Failures and limitations observed

- The first development-tool installation attempt followed `requirements.txt`
  and failed because the configured package index exposes only `aleapp 0.0.1`,
  while production requirements specify `aleapp>=3.2.0`. Phase 1 did not alter
  that production dependency; `requirements-dev.txt` is intentionally separate.
- The root product directory has no `.git` repository. No reviewable commit could
  be created; changes were kept additive and isolated for patch-based rollback.
- Running `mock_adb.py` creates mock dump directories and appends scan-history
  records as part of the existing harness behavior.
- Phase 1 does not implement acquisition-time provenance, immutable manifests,
  custody ledger verification, analyzer protocols/orchestration, caching,
  configuration, secrets handling, or canonical report renderers.
- Compatibility conversion cannot reconstruct v6.2 command exit codes or
  per-command timestamps. It records those provenance limitations explicitly.
