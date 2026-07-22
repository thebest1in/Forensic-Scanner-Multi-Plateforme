# Release Notes — Universal Forensic Scanner v7.0

## v7.0.0 (stable)

**Date** : 2026-07-22  
**Statut** : Release stable

### Nouveautés v7.0

- **GUI fonctionnelle** : Interface graphique CustomTkinter avec Tcl/Tk bundlé
- **Package Windows** : Exécutables autonomes (GUI + CLI) via PyInstaller
- **Branding unifié** : Version centralisée dans `version.py`
- **Bugs GUI corrigés** : `_mode_var` initialisé, `StringVar` corrigé

### Moteur forensique (validé depuis RC2)

- **12 phases d'analyse** : YARA → IOC → MVT → ALEAPP → Capa → APKiD → Quark → OTX → Entropie → Browser → Corrélation
- **14 règles YARA** : Pegasus, NoviSpy, FinSpy, Dendroid, SandroRAT, HackingTeam
- **25 000+ IPs malveillantes** : Synchronisation automatique (abuse.ch, C2IntelFeeds, ipsum, TinyCheck)
- **Score composite 0-100** : YARA (35pts) + Heuristiques (25pts) + Outils (20pts) + Intel (10pts) + Entropie/Browser/Corr (10pts)
- **Multi-plateforme** : Android (ADB), iOS (pymobiledevice3), Linux/Docker (SSH)
- **Chaîne de preuve** : HMAC-SHA256 + SHA-256 chain + package d'évidence auto
- **Remédiation** : DELETE/UPDATE/RESTRICT + containment automatisé (DNS sinkhole)
- **Timeline** : CSV avec 450 000+ événements supportés

### Validation

```text
pytest:       22/22 pass
mock_adb.py:  15/15 pass
ruff:         All checks passed
compileall:   Clean
GUI EXE:      Launches successfully
CLI EXE:      Menu + error handling functional
```

---

## v7.0.0-rc3

**Date** : 2026-07-22  
**Statut** : Release Candidate 3

### Corrections

- **RC-001 (GUI)** : Tcl/Tk vérifié et bundlé dans le package PyInstaller
- **RC-003 (Branding)** : v6.2 → VERSION depuis `version.py` dans le GUI
- **Bug `_mode_var`** : Variable non initialisée dans `__init__` → crash au 1er clic
- **Bug `_quick_scan_archive`** : Réassignation `StringVar` au lieu de `.set()`
- **Import inutile** : `hashlib`, `tkinter as tk`, `shutil` nettoyés

### Packaging

- PyInstaller 6.21.0 avec Tcl/Tk 8.6 bundlé
- GUI EXE (`UniversalForensicScanner.exe`) + CLI EXE (`UniversalForensicScanner_CLI.exe`)
- Tous les assets inclus : rules/, manifests/, adapters/, domain/, compat/

---

## v7.0.0-rc2

**Date** : 2026-07-22  
**Statut** : Release Candidate 2

### Validations

- Android Live Deep : POCO 2311DRK48G, Android 16, 18/18 artefacts, CLEAN 0/100
- Offline bugreport-poco.zip : 3 781 extraits, 3 759 indexés, 454 573 événements timeline
- APK hashing : push/chmod/execute réussi, apk_hashes.txt produit
- CLI : Invalid input returns exit code 2, Exit returns 0

### Non inclus

- GUI : Tcl/Tk init.tcl non trouvable (environnement Python/Tcl incomplet)

---

## v7.0.0-rc1

**Date** : 2026-07-22  
**Statut** : Release Candidate 1

### Moteur forensique

- 12 phases d'analyse opérationnelles
- Score composite de risque 0-100
- Scan lifecycle avec états terminaux
- YARA context vs authoritative classification
- Outil health status (ok/disabled/skipped/unavailable/error)

### Validation

```text
pytest:       24 pass
mock_adb.py:  15/15 pass
ruff:         new modules pass
mypy:         yara_context, yara_diagnostics, scan_lifecycle pass
```

---

## v6.2 (legacy)

**Date** : 2026-07  
**Statut** : Legacy, remplacé par v7.0

### Fonctionnalités

- GUI CustomTkinter avec 14 checkboxes (3 colonnes)
- Navigator avec filtre sévérité + recherche + Inspect
- Remediation panel (DELETE/UPDATE/RESTRICT)
- Containment automatisé (DNS sinkhole + isolation)
- Browser forensics (Chrome/WebView SQLite)
- Cross-tool correlation (6 règles JSON)
- Entropie Shannon (encrypted exfil detection)

### Corrections notables (v6.0 → v6.2)

- Risk score/verdict disconnect corrigé (0/100 CLEAN avec 6 hits YARA HIGH)
- Version string mismatch unifié
- Artifact count confusing corrigé
- Auto-evidence lock sur SUSPICIOUS + HIGH YARA

---

## v6.0

**Date** : 2026  
**Statut** : Legacy

### Fonctionnalités

- APKiD packer/obfuscation detection
- Quark-Engine behavioral analysis
- OTX + AbuseIPDB live intelligence
- Automated containment (DNS sinkhole, app isolation)
- 9-phase analysis pipeline
