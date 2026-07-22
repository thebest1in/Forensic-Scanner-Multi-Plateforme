# Universal Forensic Scanner v7.0 — Release Candidate Validation

Date: 2026-07-22 UTC  
Environment: Windows, Python 3.12, project root v7 CLI, POCO 2311DRK48G available

## Executive summary

The forensic CLI core and offline pipeline are operational. The existing
regression suite passes, the legacy harness passes, ADB acquisition works, APK
hash deployment has been verified on the physical POCO, and the bugreport archive
completes with internally consistent YARA/timeline results.

The project is **not release ready** because the GUI startup smoke test fails in
the current supported environment before creating a window. Active v6.2 branding
also remains in GUI/custody paths, and CLI invalid input is silently accepted.

## Evidence executed

```text
python -m pytest -q -p no:cacheprovider  -> 24 passed
python mock_adb.py                       -> 15/15 tests passed
python -m compileall ...                  -> exit 0 (cache directories locked warnings)
root imports                           -> all imports OK
python -m pip check                       -> No broken requirements found
CLI Android Live Triage                  -> exit 0, real device, reports generated
CLI Android Live Deep + all analyzers    -> exit 0, 18/18 artifacts, APK hashes produced
CLI bugreport-poco offline               -> exit 0, 3,781 extracted, 3,759 indexed,
                                             106 selected, 38 YARA scanned,
                                             454,573 timeline events
GUI python app.py                        -> exit 1, TclError: Can't find usable init.tcl
```

## Functional results

### CLI

Android Live, offline archive, exit, and repeated execution paths were exercised.
Live auto-detected `BISG5XZL9LSWZXO7`, acquired Triage and Deep profiles, and
generated canonical JSON, legacy JSON, and timeline CSV. Offline archive scanning
completed and retained aggregate-context YARA matches without escalating the
verdict.

Invalid menu input currently exits without an error or reprompt. This is a
Medium-severity UX/validation defect.

### Android Live

```text
Device: POCO 2311DRK48G
Android: 16
Serial: BISG5XZL9LSWZXO7
Deep artifacts: 18/18 attempted
APK hash script: push/chmod/execute succeeded; apk_hashes.txt produced
Verdict: CLEAN
Risk: 0/100
Exit: 0
```

Optional analyzer health was explicit: entropy/correlation succeeded, ALEAPP was
unavailable, and tools without compatible local input were skipped.

### Offline archive

```text
Archive: bugreport-poco.zip
Extracted: 3,781
Indexed: 3,759
Selected: 106
YARA scanned: 38
Timeline: 454,573 events
Verdict: CLEAN
Risk: 0/100
```

The five retained YARA matches were classified as aggregate diagnostic context or
likely false positives and did not independently escalate the verdict.

### GUI

Startup smoke test:

```text
python app.py
_tkinter.TclError: Can't find a usable init.tcl
```

This prevents validation of GUI widgets, controls, history, cancellation, and
GUI scan flows. Root cause is the current Python/Tk installation not exposing its
Tcl/Tk runtime (`Python312\tcl\tcl8.6`); this must be fixed or explicitly included
in packaging before release.

## Issue register

| ID | Severity | Issue | Impact | Reproduction | Root cause / proposed fix |
|---|---|---|---|---|---|
| RC-001 | High | GUI cannot start | GUI release path is unusable | `venv\\Scripts\\python.exe app.py` | Missing/unresolvable Tcl/Tk runtime; repair Python installation or package Tcl/Tk and add startup smoke test |
| RC-002 | Medium | Invalid CLI menu choice exits silently | Operator may think scan started or was accepted | Pipe `9` to `cli.py` | `main()` returns 0 for unknown input; reprompt and return nonzero on invalid choice |
| RC-003 | Medium | Active v6.2 branding remains | Reports/GUI/custody can disagree on release version | Search active `.py` entry points | Hardcoded strings in `app.py`, `custody.py`, `mock_adb.py`; import `version.py` in active producers; preserve historical docs |
| RC-004 | Medium | SQLite initialization logged repeatedly | Noisy logs and possible unnecessary initialization work | Run repeated mock/scan operations | History calls initialize repeatedly; use idempotent per-process/schema guard while keeping per-thread connections |
| RC-005 | Medium | Mock harness reports empty APK hashes | Regression harness does not exercise successful hash deployment | `python mock_adb.py` | Mock device intentionally lacks pushed helper behavior; add explicit partial/empty assertion and a successful push fixture |
| RC-006 | Low | `compileall` reports locked cache directories | Verification output is noisy | `python -m compileall .` | `.pytest_cache`/`pytest_tmp` are locked generated folders; exclude them in release verification or clean them between runs |
| RC-007 | Low | Broad Ruff/mypy still report legacy debt | Full static gate cannot be green | `ruff check .`, strict `mypy` | Existing legacy typing/import/style debt; scope gates to migrated modules or remediate incrementally |

## Analyzer and status review

The analyzer status vocabulary is present and distinguishes disabled, skipped,
unavailable, and successful tools. The full physical Deep run completed with
optional flags enabled; missing inputs were skipped and ALEAPP was unavailable.
No finding or score inconsistency was observed in the tested clean device/archive
cases.

## Reports and timeline

The CLI writes canonical JSON, legacy JSON, and timeline CSV. The offline run's
terminal count was 454,573 and the generator reported the same count. JSON keeps
timeline events external to avoid embedding the complete event set. Report paths
were generated under the scan output/extraction directory.

## Database and logging

SQLite scan history and custody tests passed, including tamper detection. Repeated
initialization messages remain visible during mock/repeated scans and are tracked
as RC-004. The core logger now uses an idempotent handler and disabled propagation;
the remaining noise requires lifecycle-level history initialization cleanup.

## Security and cleanup

ADB acquisition commands used for validation were read-only. APK helper deployment
uses quoted local paths, selected serial, chmod, explicit timeouts, and remote
cleanup. Original `bugreport-poco.zip` was retained. Generated runs were moved to
`_archive_workspace_cleanup_20260722`; no source or original evidence was deleted.

## Release recommendation

**NOT READY FOR RELEASE**

The decision is driven by RC-001 (GUI startup failure), not by the forensic CLI
core. Release requires the GUI runtime/package fix, invalid-input handling, active
version cleanup, and a repeat of GUI plus regression validation afterward.
