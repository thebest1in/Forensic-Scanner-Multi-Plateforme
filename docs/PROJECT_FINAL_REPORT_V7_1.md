# Universal Forensic Scanner v7.1.0 — Rapport final de validation

**Auteur :** Imad El Foudali  
**Établissement :** ISMAGI  
**Encadrant :** Khalil Boukri

**Cas de référence :** UFS-IOS-20260723-001  
**Opérateur :** Imad El Foudali (OP-001)  
**Build Git :** `725116742e4059f20228401cd623b0a89db21ba7` (`v7.0-rc2-frozen-10-g7251167-dirty`)

## Résumé exécutif

Universal Forensic Scanner est une plateforme d’analyse forensic multi-source
avec acquisition Android ADB, analyse d’archives Android, acquisition iOS Live
USB et analyse de sauvegardes iOS locales. Le moteur conserve les preuves,
produit des rapports JSON/legacy et une timeline CSV, et expose les limites des
outils au lieu de les masquer.

Le cœur CLI a été validé avec 26 tests pytest, le harness legacy 15/15, Ruff,
la compilation et des appareils réels Android et iOS. Le package GUI Windows
reste soumis à validation Tcl/Tk et machine propre.

## Architecture

```text
Source (ADB / iOS Lockdown / archive / backup)
        ↓
Acquisition read-only et copie locale
        ↓
Artefacts + hashes + provenance
        ↓
YARA / IOC / heuristiques / modules forensic / outils externes
        ↓
Corrélation + score + verdict
        ↓
ScanResult JSON canonique
        ├── forensic_report.json
        └── forensic_timeline.csv
```

Les analyseurs ne doivent jamais accéder directement à un téléphone ou à une
sauvegarde distante. Ils consomment des artefacts locaux.

## Modes CLI

1. Android Live (ADB)
2. Android Offline archive
3. iOS Live USB (sans backup)
4. iOS Offline backup
5. Exit

Le mode iOS Live utilise Lockdown et ne crée aucune sauvegarde. Les données
protégées par iOS (SMS, Safari, appels, contacts et domaines applicatifs) sont
analysées seulement lorsqu’elles existent dans une sauvegarde locale valide.

## Validations réelles

### Android

- Appareil : POCO 2311DRK48G, Android 16.
- Live Deep : 18 artefacts, APK hashing exécuté, verdict CLEAN, score 0/100.
- Live Forensic : 45 commandes, 45 artefacts, 12 findings, 6 mappings MITRE,
  verdict CLEAN, score 6/100.
- Archive `bugreport-poco.zip` : 106 artefacts sélectionnés, 38 fichiers YARA,
  454 573 événements timeline, verdict CLEAN, score 0/100.

### iOS Live

- Appareil : iPhone13,2, iOS 26.0.1, USB trusted.
- `pymobiledevice3` 10.0.4 installé.
- Acquisition Live sans backup : `device_information` acquis.
- Les artefacts backup-only sont explicitement marqués skipped.

### iOS Offline

Sauvegarde :

```text
C:/Users/imadfdl/Apple/MobileSync/Backup/00008101-0003043E1EF2001E
```

Présence vérifiée : `Manifest.db`, `Info.plist`, `Status.plist`.

Scan Deep :

- 37 822 enregistrements Manifest.db ;
- 15 groupes d’artefacts parsés ;
- 35 événements dans la timeline d’analyse ; la séparation détaillée entre
  activité appareil et événements scanner doit rester visible ;
- verdict `LOW_RISK` ;
- score `35/100` ;
- exit code `0`.

## Pegasus et YARA

Le résultat iOS contient deux correspondances `Pegasus_Zero_Click_Traces` dans
`configuration_profiles.json` et `application_domains.json`. Le contexte
contient notamment `group.com.apple.PegasusConfiguration`.

Ce nom Apple seul n’est pas une preuve suffisante d’infection. La classification
est donc contextuelle. Un indicateur Pegasus n’est classé à haute confiance que
lorsqu’il est corroboré par plusieurs sources indépendantes : IOC MVT actuel,
domaine ou processus connu, artefact horodaté et contexte technique compatible.

## Outils

```text
yara-python 4.5.4 : installé
MVT             : installé (mvt-ios.exe, mvt-android.exe)
ALEAPP          : module installé
SQLite          : support Python standard
```

Un outil `skipped_no_input`, `skipped_no_root`, `disabled` ou `unavailable` ne
doit pas être présenté comme exécuté. Ces limites sont conservées dans le
rapport.

## Intégrité et sécurité

- Les mots de passe de backup chiffré sont demandés avec `getpass`.
- Aucun mot de passe n’est écrit dans les logs, rapports ou configurations.
- Les backups originaux ne sont pas modifiés.
- Les sorties dérivées sont écrites dans un dossier séparé.
- Les hashes SHA-256 et la custody doivent être vérifiés séparément ; un hash
  seul ne prouve pas toute la soundness forensic.

## Tests

```text
pytest: 26 passed
legacy mock harness: 15/15
Ruff CLI: passed
Python compilation: passed
Imports CLI/core/adapters: passed
```

## Limites restantes

- Les schémas iOS changent selon la version et le modèle.
- SMS, contacts et Safari peuvent être absents ou incompatibles.
- Certains plist sont invalides, chiffrés ou non accessibles.
- Une détection YARA isolée n’est pas une confirmation Pegasus.
- Le GUI et le packaging Windows doivent encore être validés sur une machine
  propre avant la release stable globale.

## Tableau de validation iOS Offline

| Élément | État |
|---|---|
| Backup ouvert | Réussi |
| Manifest analysé | Réussi — 37 822 records |
| SMS | Échec de schéma (`m.cache_username`) |
| Contacts | Échec de schéma (`ABPerson`) |
| Historique des appels | Non trouvé |
| Safari | Non trouvé |
| MVT | Non exécuté dans ce scan |
| YARA | Exécuté — match contextuel probable |
| Verdict technique | `COMPLETED_WITH_LIMITATIONS` à documenter dans le prochain schéma |
| Compromission confirmée | Non |

## Provenance et reproductibilité

Les versions d’outils sont consignées dans `docs/DATA_SOURCES.md`. Avant une
release, le manifeste doit aussi contenir le commit Git, le hash du ruleset
YARA, le hash/date des IOC, la version ATT&CK, l’OS hôte, Python, SQLite et les
hashes de `Manifest.db`, `Info.plist` et `Status.plist`.

Le fichier local `rules/known_ips.txt` contient un commentaire indiquant des
origines mixtes (`abuse.ch`, `AbuseIPDB`, infrastructure spyware connue). Aucun
fournisseur unique, date de récupération, licence ou manifeste de hash n’est
encore prouvé par le dépôt ; le rapport ne lui attribue donc pas de fournisseur
unique.

## Conclusion

Le CLI forensic est un Release Candidate solide et reproductible. La prochaine
étape est de finaliser le GUI/package Windows, puis de refaire la campagne
d’acceptance complète avant de publier `v7.1.0` stable.
