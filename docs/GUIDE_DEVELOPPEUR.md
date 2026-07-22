# Guide Développeur — Universal Forensic Scanner v7.0

## Architecture

Le projet suit une architecture en couches :

```
┌─────────────────────────────────────────────┐
│  Interface (GUI: app.py / CLI: cli.py)       │
├─────────────────────────────────────────────┤
│  Orchestration (scan_lifecycle.py)           │
├──────────┬──────────┬───────────────────────┤
│ Acquisition│ Analyse  │ Post-traitement      │
│ extractor.py│analyzer.py│timeline/custody/    │
│ adapters/  │ bridges/ │remediation/containment│
├──────────┴──────────┴───────────────────────┤
│  Domaine (domain/) + Compatibilité (compat/) │
├─────────────────────────────────────────────┤
│  Infrastructure (core.py, history_db.py)     │
└─────────────────────────────────────────────┘
```

## Conventions de code

- **Python 3.12+** avec type hints (union syntax `X | None`)
- **Ruff** : linting avec `line-length=120`, rules `E/F/I/UP/B`
- **Pytest** : tests dans `tests/`, naming `test_*.py`
- **Imports** : triés par ruff (isort), stdlib → third-party → local
- **Docstrings** : non requis sauf pour les fonctions publiques API
- **Comments** : éviter sauf pour expliquer la logique métier complexe

## Structure des modules

### Couche Interface

| Module | Rôle |
|--------|------|
| `app.py` | GUI CustomTkinter — 1800+ lignes |
| `cli.py` | CLI en ligne de commande |

### Couche Orchestration

| Module | Rôle |
|--------|------|
| `scan_lifecycle.py` | Machine à états : INITIALIZING → INGESTING → ANALYZING → ... → COMPLETED |

### Couche Acquisition

| Module | Rôle |
|--------|------|
| `extractor.py` | Exécution des commandes ADB basées sur les manifests |
| `usb_monitor.py` | Surveillance USB (DISCONNECTED/UNAUTHORIZED/READY) |
| `archive_engine.py` | Ingestion d'archives ZIP offline |
| `adapters/` | Adaptateurs multi-plateformes (Android, iOS, Linux/Docker) |

### Couche Analyse

| Module | Rôle |
|--------|------|
| `analyzer.py` | Pipeline 12 phases : YARA → IOC → MVT → ALEAPP → Capa → APKiD → Quark → OTX → Entropie → Browser → Corrélation |
| `heuristiques.py` | Scoring basé sur les permissions |
| `yara_context.py` | Classification authoritative vs contextuelle |
| `yara_diagnostics.py` | Collecte de preuves YARA |

### Bridges (outils externes)

| Module | Outil |
|--------|-------|
| `mvt_bridge.py` | Mobile Verification Toolkit |
| `aleapp_bridge.py` | ALEAPP |
| `capa_bridge.py` | Mandiant Capa |
| `apkid_bridge.py` | APKiD |
| `quark_bridge.py` | Quark-Engine |
| `intel_bridge.py` | OTX + AbuseIPDB |
| `entropy_bridge.py` | Entropie Shannon |
| `pcap_bridge.py` | Capture réseau |
| `browser_forensics_bridge.py` | Chrome/WebView forensics |
| `correlation_engine.py` | Corrélation croisée |
| `mobsf_bridge.py` | MobSF REST API |

### Couche Post-traitement

| Module | Rôle |
|--------|------|
| `timeline.py` | Génération CSV timeline |
| `custody.py` | Chaîne de garde (HMAC-SHA256, SHA-256 chain) |
| `remediation_engine.py` | Actions DELETE/UPDATE/RESTRICT |
| `containment_engine.py` | Containment automatisé (DNS sinkhole, isolation) |

### Infrastructure

| Module | Rôle |
|--------|------|
| `core.py` | Logger, ADB wrapper, constantes |
| `history_db.py` | Base SQLite historique + delta |
| `ioc_sync.py` | Synchronisation des feeds IOC |
| `version.py` | Version centralisée |

### Domaine

| Module | Rôle |
|--------|------|
| `domain/artifact.py` | Dataclass immutable Artifact |
| `domain/event.py` | Dataclass immutable Event |
| `domain/finding.py` | Dataclass immutable Finding |
| `domain/enums.py` | Énumérations (Severity, Verdict, etc.) |
| `domain/scan_result.py` | Résultat de scan agrégé |
| `domain/scan_context.py` | Contexte de scan |

## Ajouter un nouvel outil d'analyse

1. Créer `mon_outil_bridge.py` avec une fonction `run(tool_input) -> dict`
2. Ajouter l'import dans `analyzer.py` et l'intégrer au pipeline
3. Ajouter un paramètre `run_mon_outil: bool` à `analyze()`
4. Ajouter une checkbox dans `app.py` (section ANALYSIS)
5. Ajouter dans `cli.py` si nécessaire
6. Ajouter les hidden imports dans `UniversalForensicScanner.spec`

## Tests

```bat
:: Suite de tests
venv\Scripts\python.exe -m pytest -q

:: Harness mock ADB
venv\Scripts\python.exe mock_adb.py

:: Linting
venv\Scripts\ruff check cli.py version.py app.py

:: Compilation
venv\Scripts\python.exe -m compileall . -q -x "(venv|__pycache__|\.pytest_cache|pytest_tmp|_archive)"
```

## Packaging

```bat
:: Installer PyInstaller
venv\Scripts\pip install pyinstaller

:: Build
venv\Scripts\pyinstaller.exe UniversalForensicScanner.spec --noconfirm

:: Résultat dans dist/UniversalForensicScanner/
```

## Ajouter des règles YARA

1. Éditer `rules/poco_rules.yar`
2. Chaque règle doit avoir des tags et une sévérité (low/medium/high/critical)
3. Tester la compilation : `python -c "import yara; yara.compile('rules/poco_rules.yar')"`
4. Les règles sont automatiquement chargées au démarrage

## Conventions de nommage

| Type | Convention | Exemple |
|------|-----------|---------|
| Module | `snake_case.py` | `analyzer.py` |
| Classe | `PascalCase` | `ScanLifecycle` |
| Fonction | `snake_case()` | `analyze()` |
| Variable | `snake_case` | `device_serial` |
| Constante | `UPPER_SNAKE` | `VERSION` |
| Test | `test_<description>` | `test_clean_device` |
