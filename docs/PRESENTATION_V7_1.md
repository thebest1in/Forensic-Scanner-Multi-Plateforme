# Universal Forensic Scanner v7.1.0
## Présentation de projet — CLI forensic multi-plateforme

**Auteur :** Imad El Foudali · **Établissement :** ISMAGI · **Encadrant :** Khalil Boukri

**Cas :** UFS-IOS-20260723-001 · **Opérateur :** Imad El Foudali (OP-001)

---

## 1. Problème et objectif

Les investigations mobiles produisent des données hétérogènes, des outils
optionnels et des limites d’accès. L’objectif est de fournir une chaîne
reproductible : acquisition locale, analyse contextualisée, corrélation,
rapport canonique et limites explicites.

---

## 2. Architecture de bout en bout

```text
ADB / iOS Lockdown / ZIP / iOS Backup
              ↓
Acquisition read-only + provenance
              ↓
Artefacts locaux + hashes
              ↓
YARA · IOC · heuristiques · modules forensic
              ↓
Corrélation · score · verdict
              ↓
JSON canonique · rapport legacy · timeline CSV
```

Le moteur d’analyse ne dépend pas directement du téléphone ou de la source.

---

## 3. Modes CLI

```text
1. Android Live (ADB)
2. Android Offline archive
3. iOS Live USB (no backup)
4. iOS Offline backup
5. Exit
```

Le mode iOS Live n’effectue aucune sauvegarde. Le mode Offline analyse une
copie locale Apple contenant `Manifest.db`, `Info.plist` et `Status.plist`.

---

## 4. Validation Android réelle

```text
POCO 2311DRK48G · Android 16
Live Deep: 18 artefacts · CLEAN · 0/100
Live Forensic: 45 artefacts · 12 findings · 6 MITRE · CLEAN · 6/100
Bugreport offline: 454 573 événements timeline · CLEAN · 0/100
```

Ces résultats démontrent la continuité acquisition → analyse → rapport.

---

## 5. Validation iOS Live

```text
iPhone13,2
iOS 26.0.1
USB trusted
pymobiledevice3 10.0.4
```

L’acquisition Live a récupéré les informations Lockdown. Les données protégées
par iOS restent limitées sans backup, ce qui est signalé au lieu d’être inventé.

---

## 6. Validation iOS Offline

```text
Backup: 00008101-0003043E1EF2001E
Manifest.db: 37 822 enregistrements
Artefacts: 15 groupes
Timeline d’analyse: 35 événements
Événements iOS issus des bases appareil: à confirmer séparément
Score: 35/100
Verdict: LOW_RISK
Exit code: 0
```

Les rapports JSON, legacy et CSV ont été générés.

---

## 7. Détection Pegasus : interprétation défendable

Deux correspondances `Pegasus_Zero_Click_Traces` ont été trouvées dans des
artefacts de configuration et domaines applicatifs.

Le nom Apple `group.com.apple.PegasusConfiguration` seul n’est pas une preuve
d’infection. Un indicateur Pegasus n’est classé à haute confiance que lorsqu’il
est corroboré par plusieurs sources indépendantes : IOC MVT actuel, domaine ou
processus connu, artefact horodaté et contexte technique compatible.

Une détection YARA isolée ne suffit jamais à confirmer Pegasus.

---

## 8. Outils et couverture

```text
YARA / yara-python: 4.5.4
MVT: mvt-ios.exe, mvt-android.exe
ALEAPP: installé
SQLite: Python standard library
```

Les états `skipped_no_input`, `skipped_no_root`, `disabled` et `unavailable`
restent visibles dans les rapports. Un outil non exécuté n’est pas présenté
comme une preuve négative.

---

## 9. Sécurité des preuves

- sauvegardes originales non modifiées ;
- sorties dérivées séparées ;
- hashes et provenance ;
- mots de passe demandés à l’exécution avec `getpass` ;
- aucun secret dans les logs ou rapports ;
- JSON canonique comme source de vérité.

---

## 10. Qualité logicielle

```text
pytest: 26 passed
Legacy harness: 15/15
Ruff CLI: passed
Compilation: passed
Imports: passed
```

Le cycle de vie CLI est terminal et les échecs d’outils optionnels sont isolés.

---

## 11. Limites actuelles

- les schémas SQLite iOS varient selon les versions ;
- certaines bases peuvent être absentes ;
- certains plist sont invalides ou chiffrés ;
- les outils externes peuvent manquer d’entrée ou de binaire ;
- le GUI et le packaging Windows nécessitent encore une validation sur machine
  propre.

---

## 12. Conclusion et feuille de route

Le CLI forensic est un Release Candidate solide et reproductible.

```text
RC2: moteur CLI validé et gelé
RC3: GUI + Tcl/Tk + packaging Windows
RC4: acceptance complète CLI + GUI
v7.1.0 stable: après validation machine propre
```

La priorité est la fiabilité de distribution, pas l’ajout de nouvelles
fonctionnalités de détection.
