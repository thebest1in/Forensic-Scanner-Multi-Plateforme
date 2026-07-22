# Universal Forensic Scanner v7.0-rc3 — CLI Program Guide

Run `run_cli.bat` from the project root. The menu supports Android Live,
offline archive analysis, and exit. JSON is the canonical result; timeline CSV
and other reports are derived outputs.

## GUI + CLI Package

```bat
dist\UniversalForensicScanner\UniversalForensicScanner.exe        # GUI
dist\UniversalForensicScanner\UniversalForensicScanner_CLI.exe    # CLI
```

Both EXEs are self-contained with Tcl/Tk bundled. No Python installation required.

## Verified 2026-07-22

```text
Android Live Deep: POCO 2311DRK48G, Android 16, 18 artifacts, CLEAN, 0/100
Offline bugreport-poco.zip: 454,573 timeline events, CLEAN, 0/100
pytest: 22/22 pass | legacy harness: 15/15 | Ruff CLI: passed
GUI EXE: Launches successfully, branding correct
CLI EXE: Menu + error handling functional
```

Invalid menu input returns exit code 2; Exit returns 0. APK hashing uses the
selected ADB serial, explicit push/chmod/execute timeouts, captured output, and
remote cleanup. Disabled and no-input analyzers are not treated as warnings.

## Documentation

| Document | Description |
|----------|-------------|
| `docs/GUIDE_UTILISATEUR.md` | Guide utilisateur complet |
| `docs/GUIDE_ENQUETEUR.md` | Guide enquêteurs forensiques |
| `docs/GUIDE_INSTALLATION.md` | Instructions d'installation |
| `docs/GUIDE_DEVELOPPEUR.md` | Guide développeur |
| `docs/LIMITATIONS.md` | Limitations connues |
| `docs/RELEASE_NOTES.md` | Notes de version |
| `docs/LICENCES.md` | Licences et attributions |
