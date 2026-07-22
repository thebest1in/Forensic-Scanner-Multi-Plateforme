# Guide Enquêteur — Universal Forensic Scanner v7.0

## Avertissement

Cet outil est conçu pour l'analyse forensique de smartphones Android. Les résultats
doivent être interprétés par un enquêteur qualifié. Un verdict "CLEAN" ne garantit
pas l'absence de malware — il indique que les analyseurs disponibles n'ont détecté
aucune menace.

## Chaîne de preuve

### Intégrité des données

- Chaque artefact extrait est horodaté et tracé (SHA-256)
- Le rapport JSON contient les métadonnées complètes de chaque analyse
- Les résultats HMAC-SHA256 et SHA-256 chain保证 l'intégrité de la chaîne de preuve
- Les packages d'évidence signés incluent les résultats de chaque outil d'analyse

### Collecte d'artefacts

#### Profil Triage (4 artefacts — analyse rapide)
1. `device_info.txt` — Propriétés système (getprop)
2. `netstat.log` — Connexions réseau actives
3. `third_party_apps.txt` — Applications tierces installées
4. `processes.txt` — Processus en cours d'exécution

#### Profil Deep (18 artefacts — analyse complète)
Ajoute : system_apps, batterystats, logcat, meminfo, wifi, location, notifications,
accounts, lock_settings, usb_history, accessibility_services, device_admin,
vpn_config, apk_hashes

### Analyse à 12 phases

| Phase | Outil | Détecte |
|-------|-------|---------|
| 1 | Filtre bruit | Réduction ~30% des logs non pertinents |
| 2 | YARA (14 règles) | Pegasus, NoviSpy, FinSpy, Dendroid, SandroRAT, HackingTeam, reverse shells |
| 3 | IOC (25 000+ IPs) | IP malveillantes connues (abuse.ch, C2IntelFeeds, ipsum, TinyCheck) |
| 4 | MVT | Spywares mobiles (Pegasus, Predator, FinSpy) |
| 5 | ALEAPP | Artefacts Android profonds, détection stalkerware |
| 6 | Capa | Capacités malveillantes statiques (keylogger, reverse shell, C2) |
| 7 | APKiD | Packers, obfuscation, techniques anti-analyse |
| 8 | Quark | Comportements malveillants bytecode Dalvik |
| 9 | OTX + AbuseIPDB | Intelligence threat en temps réel |
| 10 | Entropie Shannon | Détection exfiltration chiffrée / obfuscation |
| 11 | Browser Forensics | Historique Chrome/WebView, URLs suspectes |
| 12 | Corrélation croisée | Événements liés entre outils par package |

### Classifications YARA

| Type | Description | Impact verdict |
|------|-------------|----------------|
| **Authoritative** | Fichier artifact ciblé (APK, binaire) | Oui — peut escalader le verdict |
| **Contextual** | Bugreport agrégé (fichier diagnostic) | Non — retenu comme contexte |

Seuls les matches **authoritative** dans des artefacts ciblés peuvent escalader
le verdict. Les matches dans un bugreport agrégé sont classifiés comme contextuels
pour éviter les faux positifs.

## Interprétation des résultats

### Score composite

Le score 0-100 combine six sources :

```
YARA (35pts) + Heuristiques (25pts) + Outils (20pts) + Intel (10pts) + Entropie/Browser/Corr (10pts)
```

- **0-29** : CLEAN — Aucune menace significative
- **30-69** : SUSPICIOUS — Activité suspecte nécessitant investigation
- **70-100** : CRITICAL — Menace confirmée, actions requises

### Actions de remédiation

| Action | Description | Commande ADB |
|--------|-------------|--------------|
| **DELETE** | Désinstaller le package pour l'utilisateur actuel | `adb shell pm uninstall --user 0 <package>` |
| **UPDATE** | Mettre à jour un composant | Recommandation manuelle |
| **RESTRICT** | Restreindre les permissions | Via Containment Engine |

## Conservation des preuves

### Package d'évidence

Lors d'un verdict SUSPICIOUS ou CRITICAL avec un score élevé, un package d'évidence
est automatiquement créé :

- Fichiers sources signés (HMAC-SHA256)
- Résultats de chaque outil d'analyse
- Chaîne de hash SHA-256
- Métadonnées de chaîne de garde

### Conteneur chiffré

Activez **Encrypt CRITICAL** pour créer un ZIP AES-256 chiffré contenant tous
les artefacts et résultats.

## Limites forensiques

1. **ADB requis** : L'acquisition live nécessite le débogage USB activé
2. **Permissions** : Certains artefacts nécessitent un appareil rooté
3. **Outils optionnels** : MVT/ALEAPP/Capa/APKiD/Quark peuvent ne pas être installés
4. **Bugreport agrégé** : Les matches YARA dans un bugreport sont contextuels
5. **Environnement** : Analyse sur poste de travail, pas sur environnement contrôlé
6. **Chaîne de preuve** : SHA-256 garantit l'intégrité mais ne prouve pas la conformité forensique complète

## Documentation réglementaire

Les résultats de cet outil doivent être accompagnés de :
- Date/heure UTC de l'analyse
- Version de l'outil et des règles YARA
- Modèle/firmware de l'appareil analysé
- Profil d'acquisition utilisé
- Liste des outils optionnels activés/désactivés
- Limitations connues
