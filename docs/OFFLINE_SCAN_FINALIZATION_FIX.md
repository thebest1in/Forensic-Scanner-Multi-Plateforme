# Offline scan finalization freeze

Date: 2026-07-22

## Confirmed cause

The observed log sequence did not stop inside remediation. `analyze_remediation()`
contains no subprocess, wait, lock, executor, or unbounded loop. The timeline log
also proves that remediation returned and execution advanced through report and
timeline generation.

The visible freeze was a lifecycle/UI defect in `app.py`:

1. `analyze()` emitted component-local progress `100`.
2. `_run_archive_scan()` then reset global GUI progress to `80` with the label
   `Running remediation analysis...`.
3. Report and timeline generation emitted terminal logs but no later global
   progress update.
4. The worker merely queued `_show_results`; there was no centralized terminal
   callback that guaranteed progress completion and control restoration.
5. Some navigator/progress calls were made directly from worker code rather than
   being marshalled consistently to Tk's event thread.

Therefore a scan could finish its disk work while the last visible progress state
remained at remediation. This was not a SQLite deadlock: connections in the
history path are committed and closed, and the scan-history log precedes analysis
completion. It was also not caused by inserting 454,573 timeline rows into a Tk
widget; `timeline.py` writes them to CSV in the worker. That volume can still make
timeline generation slow, so it now has an explicit timeout.

## Correction

- Added explicit `ScanStage` terminal states and a thread-safe lifecycle record.
- Mapped analyzer-local progress into the global 20–70% range.
- Added distinct remediation, reporting, timeline, and finalizing progress.
- Added bounded post-analysis execution:
  - ingestion: 300 seconds;
  - remediation: 30 seconds;
  - report: 30 seconds;
  - timeline: 180 seconds;
  - optional encrypted package: 300 seconds.
- Avoided `ThreadPoolExecutor` for timeout enforcement because executor shutdown
  can wait forever for a stuck worker. A daemon stage worker returns control to
  the scan lifecycle on timeout. Python cannot safely kill the timed-out thread;
  this limitation is explicit.
- Centralized UI completion in `_finalize_scan_ui()`. Its `finally` block always
  publishes 100% plus one explicit terminal state and restores buttons.
- Unified the legacy offline worker with the same archive finalization path.
- Optional analyzer failures produce `COMPLETED_WITH_WARNINGS` rather than an
  indefinitely non-terminal scan.

## Risk score versus verdict

The score and verdict serve different purposes in the existing v6.2 policy:

- The weighted score is capped by category weights and can produce `35/100
  (LOW_RISK)` when optional analyzers are unavailable.
- `_compute_verdict()` is authoritative and escalates to `CRITICAL` when a
  high-confidence YARA policy tag such as `data_exfil`, `credential_theft`, or
  `disguised_package` is present.

The detection policy was not changed. Reports and GUI results now expose both the
weighted band and authoritative verdict, plus explicit escalation reasons. This
removes the apparent contradiction without weakening or hiding detection.

## Verification

```text
pytest: 16 passed in 0.44s
Ruff (new lifecycle/tests): All checks passed!
mypy (new lifecycle): Success: no issues found in 1 source file
legacy mock harness: 15/15 tests passed
imports: offline finalization imports OK
```

The full GUI was not launched automatically during headless verification. The UI
finalizer and progress scaling are tested through lightweight fake GUI objects.
Real interactive validation should repeat the original large archive scan and
confirm `COMPLETED_WITH_WARNINGS` after timeline generation.
