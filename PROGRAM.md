# Universal Forensic Scanner v7.0 RC2 — CLI Program Guide

Run `run_cli.bat` from the project root. The menu supports Android Live,
offline archive analysis, and exit. JSON is the canonical result; timeline CSV
and other reports are derived outputs.

## Verified 2026-07-22

```text
Android Live Deep: POCO 2311DRK48G, Android 16, 18 artifacts, CLEAN, 0/100
Offline bugreport-poco.zip: 454,573 timeline events, CLEAN, 0/100
pytest: 26 passed | legacy harness: 15/15 | Ruff CLI: passed
```

Invalid menu input returns exit code 2; Exit returns 0. APK hashing uses the
selected ADB serial, explicit push/chmod/execute timeouts, captured output, and
remote cleanup. Disabled and no-input analyzers are not treated as warnings.

## Known limitation

The GUI is not release-ready on this machine because the Python runtime cannot
load Tcl/Tk (`_tkinter: Can't find a usable init.tcl`). Repair or package Tcl/Tk
before declaring the combined GUI distribution ready.
