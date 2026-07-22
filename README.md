# Universal Forensic Scanner

**Version** : 7.0.0  
**Date** : 2026-07-22  
**Statut** : Release Candidate 3 (GUI + Packaging validés)

## Description

Outil d'analyse forensique universel pour smartphones Android, iOS et Linux/Docker.
Analyse à 12 phases avec détection de spywares, scoring de risque composite et
chaîne de preuve intégrée.

## Fonctionnalités

- **3 modes d'analyse** : Android Live (ADB), Archive offline, Scan live
- **12 phases d'analyse** : YARA, IOC, MVT, ALEAPP, Capa, APKiD, Quark, OTX, Entropie, Browser, Corrélation
- **14 règles YARA** : Pegasus, NoviSpy, FinSpy, Dendroid, SandroRAT, HackingTeam
- **25 000+ IPs malveillantes** : Synchronisation automatique
- **Score composite 0-100** : YARA + Heuristiques + Outils + Intel + Entropie
- **Multi-plateforme** : Android, iOS, Linux/Docker
- **GUI + CLI** : Interface graphique CustomTkinter + ligne de commande
- **Chaîne de preuve** : HMAC-SHA256, SHA-256 chain, packages d'évidence
- **Remédiation** : Actions DELETE/UPDATE/RESTRICT
- **Containment** : DNS sinkhole, isolation apps, evidence lock

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

Voir `docs/GUIDE_INSTALLATION.md` pour les détails complets.

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
# 2. Offline archive
# 3. Exit
```

Voir `docs/GUIDE_UTILISATEUR.md` pour les détails complets.

## Documentation

| Document | Description |
|----------|-------------|
| `docs/GUIDE_UTILISATEUR.md` | Guide utilisateur complet |
| `docs/GUIDE_ENQUETEUR.md` | Guide pour enquêteurs forensiques |
| `docs/GUIDE_INSTALLATION.md` | Instructions d'installation |
| `docs/GUIDE_DEVELOPPEUR.md` | Guide développeur |
| `docs/LIMITATIONS.md` | Limitations connues |
| `docs/RELEASE_NOTES.md` | Notes de version |
| `docs/LICENCES.md` | Licences et attributions |
| `docs/FULL_FORENSIC_REPORT.md` | Rapport forensique complet (POCO 2311DRK48G) |
| `PROJECT_MAP.md` | Carte du projet et architecture |
| `PROGRAM.md` | Guide programme CLI |

## Validation

```text
pytest:       22/22 pass
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
