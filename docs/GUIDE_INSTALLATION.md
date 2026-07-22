# Guide d'installation — Universal Forensic Scanner v7.0

## Option 1 : Exécutable Windows (recommandé)

### Prérequis

- Windows 10/11 64-bit
- ADB (Android SDK Platform-Tools) — [Télécharger](https://developer.android.com/tools/releases/platform-tools)

### Installation

1. Extraire l'archive `UniversalForensicScanner-v7.0.zip`
2. Placer les outils ADB dans le sous-dossier `tools/` ou ajouter au PATH
3. Lancer `UniversalForensicScanner.exe` (GUI) ou `UniversalForensicScanner_CLI.exe` (CLI)

### Structure du package

```
UniversalForensicScanner/
├── UniversalForensicScanner.exe       ← Interface graphique
├── UniversalForensicScanner_CLI.exe   ← Ligne de commande
├── _internal/
│   ├── tcl8.6/                        ← Runtime Tcl/Tk
│   ├── tk8.6/                         ← Runtime Tk
│   ├── customtkinter/                 ← Framework GUI
│   ├── rules/                         ← Règles YARA + IOC
│   │   ├── poco_rules.yar             ← 14 règles de détection
│   │   ├── known_ips.txt              ← 25 000+ IPs malveillantes
│   │   └── scans.db                   ← Base SQLite historique
│   ├── manifests/                     ← Manifests d'extraction
│   ├── adapters/                      ← Adaptateurs multi-plateformes
│   ├── domain/                        ← Modèles de domaine
│   ├── compat/                        ← Compatibilité v6
│   ├── docs/                          ← Documentation
│   └── scripts/                       ← Scripts utilitaires
├── config/                            ← Configuration (à créer)
├── tools/                             ← Outils externes (ADB, etc.)
├── reports/                           ← Rapports générés
├── logs/                              ← Journaux d'exécution
└── docs/                              ← Documentation utilisateur
```

## Option 2 : Depuis les sources

### Prérequis

- Python 3.12+ (recommandé : 3.12.10)
- Git
- pip

### Installation

```bat
:: Cloner le dépôt
git clone <url-du-depot>
cd SECURITY\ PHONE

:: Créer l'environnement virtuel
python -m venv venv
venv\Scripts\activate

:: Installer les dépendances
pip install -r requirements.txt
pip install -r requirements-dev.txt  # optionnel : outils de développement

:: Vérifier l'installation
python -c "import tkinter as tk; r=tk.Tk(); print('Tk OK'); r.destroy()"
python -m pytest -q
python mock_adb.py
```

### Lancement

```bat
:: GUI
venv\Scripts\python.exe app.py

:: CLI
venv\Scripts\python.exe cli.py

:: Ou utiliser les lanceurs
run.bat      ← GUI
run_cli.bat  ← CLI
```

## Configuration ADB

### Windows

1. Télécharger [Android SDK Platform-Tools](https://developer.android.com/tools/releases/platform-tools)
2. Extraire dans un dossier (ex: `C:\platform-tools`)
3. Ajouter au PATH système :
   - Paramètres → Système → Informations système → Paramètres système avancés
   - Variables d'environnement → Path → Ajouter le chemin

### Vérification

```bat
adb devices
```

L'appareil doit apparaître avec le statut `device` (pas `unauthorized`).

### Débogage USB

1. Paramètres → À propos du téléphone → Numéro de build (tap 7 fois)
2. Paramètres → Options de développement → Débogage USB → Activer
3. Connecter l'appareil et accepter la clé RSA

## Outils optionnels

| Outil | Usage | Installation |
|-------|-------|-------------|
| MVT | Détection spyware | `pip install mvt` |
| ALEAPP | Artefacts Android | `pip install aleapp` |
| Capa | Analyse statique | `pip install capa` |
| APKiD | Détection packers | `pip install apkid` |
| Quark | Analyse comportementale | `pip install quark-engine` |
| MobSF | Framework sécurité | `pip install mobsf` |

## Mise à jour des IOC

Les feeds IOC sont automatiquement synchronisés au démarrage :
- abuse.ch IP Threat Intel
- C2 IntelFeeds - Known C2 IPs
- stamparm IPsum (level 3+)
- TinyCheck Stalkerware IPs

Pour forcer une synchronisation manuelle, relancez l'application.

## Dépannage

| Problème | Solution |
|----------|----------|
| `init.tcl` introuvable | Réinstaller Python avec Tcl/Tk ou utiliser l'exécutable Windows |
| ADB non trouvé | Vérifier le PATH ou placer ADB dans `tools/` |
| Appareil `unauthorized` | Accepter la clé RSA sur l'écran de l'appareil |
| `tkinter` introuvable | `pip install customtkinter` ou réinstaller Python |
| YARA compile error | Vérifier `rules/poco_rules.yar` — ne pas modifier les noms de règles |
