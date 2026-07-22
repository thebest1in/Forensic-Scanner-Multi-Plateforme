# Limitations — Universal Forensic Scanner v7.0

## Limitations fonctionnelles

### Acquisition

| Limite | Description | Impact |
|--------|-------------|--------|
| ADB requis | L'acquisition Android live nécessite le débogage USB activé | Impossible sur appareils verrouillés sans USB debugging |
| Permissions | Certains artefacts (accessibility, device_admin) nécessitent des permissions élevées | Artefacts partiels sans root |
| Appareil connecté | Le mode live nécessite une connexion USB physique | Pas d'acquisition à distance (sauf SSH pour Linux) |
| iOS limité | L'adaptateur iOS utilise pymobiledevice3, fonctionnalités réduites par rapport à ADB | Artefacts iOS plus limités |
| Un seul appareil | L'acquisition traite un appareil à la fois | Pas de scan parallèle multi-appareils |

### Analyse

| Limite | Description | Impact |
|--------|-------------|--------|
| Outils optionnels | MVT/ALEAPP/Capa/APKiD/Quark peuvent ne pas être installés | Couverture réduite si outils manquants |
| ALEAPP indisponible | ALEAPP nécessite un environnement spécifique | Phase 5 parfois skippée |
| Faux positifs YARA | Les matches dans les bugreports agrégés sont classifiés comme contextuels | Peut sous-estimer dans certains cas |
| IOC feed | Les feeds IOC dépendent de sources externes (abuse.ch, etc.) | Pas d'analyse si pas de connexion internet |
| Scores heuristiques | Basés sur des combos de permissions connus | Peut manquer des patterns inédits |

### Reporting

| Limite | Description | Impact |
|--------|-------------|--------|
| Pas de PDF | La génération de rapports PDF n'est pas encore implémentée | Export uniquement en JSON/CSV |
| Pas de HTML interactif | L'interface HTML n'est pas encore implémentée | Pas de visualisation interactive |
| Timeline volumineuse | Les bugreports peuvent contenir des centaines de milliers d'événements | Rendu GUI limité à ~500-1000 événements |

## Limitations techniques

### Environnement

| Limite | Description |
|--------|-------------|
| Windows uniquement | Le package PyInstaller est construit pour Windows 64-bit |
| Python 3.12+ | Requis pour la syntaxe modern (`X | None`) |
| Tcl/Tk | Nécessaire pour le GUI (inclus dans le package Windows) |
| Espace disque | Les bugreports peuvent faire 30-50 MB ; les artefacts extraits 100+ MB |

### Performance

| Limite | Description |
|--------|-------------|
| Analyse CPU | 12 phases d'analyse peuvent prendre 30-120 secondes |
| Mémoire | Les gros bugreports peuvent consommer 500 MB+ de RAM |
| YARA | L'analyse de milliers de fichiers est CPU-intensive |
| Timeline | La génération de 450 000+ événements prend 30-60 secondes |

### Sécurité

| Limite | Description |
|--------|-------------|
| SHA-256 | L'intégrité est garantie mais pas la conformité forensique complète |
| ADB | Les commandes ADB sont exécutées avec les permissions de l'appareil connecté |
| Chiffrement | L'option Encrypt crée un ZIP AES-256 mais la clé est gérée localement |
| Pas de sandbox | L'application tourne avec les permissions de l'utilisateur courant |

## Limitations forensiques

1. **Environnement non contrôlé** : L'analyse est effectuée sur un poste de travail Windows, pas dans un environnement forensique certifié
2. **Acquisition non prouvée** : L'acquisition ADB standard ne garantit pas l'absence de modification de l'appareil
3. **Pas de write-blocker** : L'acquisition live peut modifier des métadonnées de l'appareil
4. **Horodatages** : Les horodatages dépendent de l'horloge de l'appareil, pas d'une source externe
5. **Chaîne de garde** : La chaîne de preuve est interne à l'outil ; elle doit être complétée par des procédures organisationnelles

## Versions connues

| ID | Sévérité | Description | Statut |
|----|----------|-------------|--------|
| RC-002 | Moyen | Choix CLI invalide exit silencieusement | Corrigé dans RC3 |
| RC-003 | Moyen | Branding v6.2 restant | Corrigé dans RC3 |
| RC-004 | Moyen | Initialisation SQLite bruyante | Connue |
| RC-005 | Moyen | Mock harness APK hashes vide | Connue |
| RC-006 | Bas | compileall reporte caches verrouillés | Connue |

## Roadmap des améliorations

| Priorité | Amélioration |
|----------|-------------|
| Haute | Rapport PDF professionnel |
| Haute | HTML interactif avec graphiques |
| Moyenne | Historique et delta entre scans |
| Moyenne | Métriques de couverture et confiance |
| Moyenne | Rapport d'inventaire packages |
| Basse | YARA on-device (ARM64) |
| Basse | Règles YARA pré-compilées (.yarc) |
| Basse | Adaptateur Windows/macOS |
| Basse | PCAP chiffré avec TLS 1.3 |
