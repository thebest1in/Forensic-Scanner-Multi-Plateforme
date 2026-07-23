# Universal Forensic Scanner

![Version](https://img.shields.io/badge/version-7.1.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)
![Python](https://img.shields.io/badge/python-3.9+-yellow)

**Version** : 7.1.0  
**Date** : 2026-07-24  
**Statut** : Release Candidate 4 (iOS Support Added)

## Description

Outil d'analyse forensique universel pour smartphones Android et iOS.
Analyse à 14 phases avec détection de spywares, scoring de risque composite et
chaîne de preuve intégrée.

## Fonctionnalités

### Modes d'analyse

- **Android Live (ADB)** — Analyse en temps réel via USB
- **Android Offline** — Analyse de dumps/archives existants
- **iOS Live (libimobiledevice)** — Extraction backup via USB
- **iOS Offline** — Analyse de backups iOS existants

### Modules d'analyse (14 phases)

| Phase | Description |
|-------|-------------|
| YARA | Détection signatures malware (18 règles) |
| IOC | Indicateurs de compromission |
| MVT | Mobile Verification Toolkit |
| ALEAPP | Android Logs Events And Logs Parser |
| Capa | Détection capacités malware |
| APKiD | Identification protections APK |
| Quark | Détection malware Android |
| OTX | AlienVault Open Threat Exchange |
| Entropie | Détection chiffrement/obfuscation |
| Browser | Analyse historique navigation |
| Corrélation | Corrélation multi-sources |
| Accessibility | Permissions accessibilité suspectes |
| APK Hash | Comparaison hashes connus |
| Device Admin | Administrateurs de périphériques |
| Install Timeline | Chronologie installations |

### Artifacts iOS (12 parsers)

- SMS/iMessage
- Appels
- Contacts
- Safari/WiFi
- Analytics
- Profils
- Domains applicatifs
- Et plus...

## Installation

### Exécutable Windows (recommandé)

```bat
# Extraire l'archive et lancer
UniversalForensicScanner.exe        # GUI
UniversalForensicScanner_CLI.exe    # CLI
```

### Depuis les sources

```bat
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
venv\Scripts\python.exe app.py      # GUI
venv\Scripts\python.exe cli.py      # CLI
```

### Prérequis iOS (optionnel)

Pour l'analyse iOS, installer Apple Devices ou iTunes depuis le Microsoft Store :
https://apps.microsoft.com/detail/9pb2mz1zmb1s

Voir `docs/IOS_ARTIFACTS.md` pour les détails complets.

## Utilisation rapide

### GUI

1. Connecter un appareil Android via USB
2. Lancer `UniversalForensicScanner.exe`
3. Cliquer sur **PULL & SCAN PHONE**
4. Attendre la fin de l'analyse
5. Consulter les résultats dans le Navigator et le panneau Results

### CLI

```bat
UniversalForensicScanner_CLI.exe
# 1. Android Live (ADB)
# 2. Android Offline
# 3. iOS Live (libimobiledevice)
# 4. iOS Offline
# 5. Exit
```

Voir `docs/GUIDE_UTILISATEUR.md` pour les détails complets.

## Architecture

```
security-phone/
├── cli.py                  # Interface ligne de commande
├── app.py                  # Interface graphique (CustomTkinter)
├── analyzer.py             # Moteur d'analyse principal
├── extractor.py            # Extraction artifacts
├── timeline.py             # Chronologie forensique
├── yara_context.py         # Scanner YARA
├── osint_bridge.py         # Intégration OSINT
├── ios/                    # Acquisition iOS
│   ├── acquisition.py      # IOSAcquirer
│   ├── backup.py           # Manifest.db parser
│   ├── parsers/            # 12 parsers iOS
│   └── ...
├── forensic_modules/       # Modules forensiques
│   ├── accessibility_analysis.py
│   ├── apk_hash_analysis.py
│   ├── mitre_mapping.py
│   └── ...
├── manifests/              # Artefacts à extraire
│   ├── android_artifacts.json
│   └── ios_artifacts.json
├── rules/                  # Règles YARA + IOCs
│   ├── scans.db
│   └── known_apk_hashes.json
└── libimobiledevice/       # Binaires Windows (exclus du repo)
```

## Documentation

| Document | Description |
|----------|-------------|
| `docs/GUIDE_UTILISATEUR.md` | Guide utilisateur complet |
| `docs/GUIDE_ENQUETEUR.md` | Guide pour enquêteurs forensiques |
| `docs/GUIDE_INSTALLATION.md` | Instructions d'installation |
| `docs/GUIDE_DEVELOPPEUR.md` | Guide développeur |
| `docs/IOS_ARTIFACTS.md` | Artifacts iOS et parsers |
| `docs/LIMITATIONS.md` | Limitations connues |
| `docs/RELEASE_NOTES.md` | Notes de version |
| `docs/LICENCES.md` | Licences et attributions |
| `docs/FULL_FORENSIC_REPORT.md` | Rapport forensique complet (POCO 2311DRK48G) |
| `PROJECT_MAP.md` | Carte du projet et architecture |
| `PROGRAM.md` | Guide programme CLI |

## Validation

```text
pytest:       34/36 pass
mock_adb.py:  15/15 pass
ruff:         All checks passed
compileall:   Clean
GUI EXE:      Launches successfully
CLI EXE:      Menu + error handling functional
```

## Licence

MIT License — Voir `LICENSE`

## Avertissement

Cet outil est conçu pour l'analyse forensique légale. Les résultats doivent être
interprétés par un enquêteur qualifié. Un verdict "CLEAN" ne garantit pas l'absence
de malware.
