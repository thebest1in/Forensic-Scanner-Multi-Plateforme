# Guide Utilisateur — Universal Forensic Scanner v7.0

## Prérequis

- Windows 10/11 (64-bit)
- ADB (Android SDK Platform-Tools) dans le PATH ou dans `tools/`
- Un appareil Android avec débogage USB activé

## Lancement

### Mode GUI (interface graphique)

```bat
UniversalForensicScanner.exe
```

ou depuis les sources :

```bat
venv\Scripts\python.exe app.py
```

### Mode CLI (ligne de commande)

```bat
UniversalForensicScanner_CLI.exe
```

ou depuis les sources :

```bat
venv\Scripts\python.exe cli.py
```

## Modes d'analyse

### 1. Android Live (ADB)

Connectez un appareil Android via USB. L'application détecte automatiquement l'appareil.

- **Triage** (4 artefacts) : rapide, ~30 secondes
- **Deep** (18 artefacts) : complet, ~2-5 minutes

Cliquez sur **PULL & SCAN PHONE** (GUI) ou sélectionnez **1** (CLI).

### 2. Analyse d'archive (offline)

Sélectionnez un fichier ZIP contenant un bugreport Android ou une sauvegarde.

Cliquez sur **SCAN ARCHIVE** (GUI) ou sélectionnez **2** (CLI) puis choisissez le fichier.

### 3. Scan Live

Analyse en temps réel de l'appareil connecté sans archivage préalable.

Cliquez sur **SCAN LIVE** (GUI).

## Options avancées (GUI)

Cliquez sur **Show Advanced Options** pour accéder aux paramètres :

| Colonne | Options |
|---------|---------|
| **ACQUISITION** | PCAP, VirusTotal, JSON Report, Timeline CSV |
| **ANALYSIS** | MVT, ALEAPP, Capa, APKiD, Quark, Entropy, Browser |
| **INTEL + ACTION** | OTX Live IP, Encrypt CRITICAL, Cross-Tool Correlation |

## Résultats

### Verdict

| Niveau | Signification |
|--------|---------------|
| **CLEAN** | Aucune menace détectée (score 0-29/100) |
| **SUSPICIOUS** | Activité suspecte détectée (score 30-69/100) |
| **CRITICAL** | Menace confirmée (score 70-100/100) |

### Score de risque composite

Le score 0-100 combine :
- Règles YARA (35 points)
- Permissions heuristiques (25 points)
- Outils externes (20 points)
- Intelligence threat (10 points)
- Entropie/Browser/Corrélation (10 points)

### Artefact Navigator

Filtrez les artefacts par sévérité (CRITICAL/SUSPICIOUS/CLEAN) ou recherchez par nom. Cliquez sur **Inspect** pour voir le contenu d'un artefact.

### Remediation

Les actions recommandées s'affichent dans les résultats :
- **DELETE** : Désinstaller un package malveillant
- **UPDATE** : Mettre à jour un composant vulnérable
- **RESTRICT** : Restreindre les permissions d'un package

## Historique

Cliquez sur **History** (GUI) pour afficher les scans précédents depuis la base SQLite.

## Fermeture

Fermez la fenêtre (GUI) ou sélectionnez **3** (CLI). Les répertoires temporaires sont automatiquement nettoyés.
