# Licences et Third-Party Notices — Universal Forensic Scanner v7.0

## Licence du projet

Le code source de l'Universal Forensic Scanner est distribué sous licence MIT.
Voir le fichier `LICENSE` à la racine du dépôt pour les détails complets.

## Dépendances et leurs licences

### Dépendances principales

| Package | Version | Licence | Usage |
|---------|---------|---------|-------|
| customtkinter | 6.0.0 | MIT | Framework GUI |
| yara-python | 4.5.4 | Apache-2.0 | Règles YARA |
| psutil | 7.2.2 | BSD-3-Clause | Monitoring système |
| requests | ≥2.31.0 | Apache-2.0 | HTTP (IOC feeds, APIs) |
| pymobiledevice3 | ≥4.0.0 | LGPL-3.0 | Forensique iOS |
| docker | ≥6.0.0 | Apache-2.0 | Conteneurs Docker |
| paramiko | ≥3.0.0 | LGPL-2.1 | SSH |
| pyzipper | ≥0.3.6 | MIT | ZIP AES-256 |

### Outils d'analyse optionnels

| Package | Version | Licence | Usage |
|---------|---------|---------|-------|
| mvt | ≥1.8.0 | MPL-2.0 | Détection spyware mobile |
| aleapp | ≥3.2.0 | Apache-2.0 | Artefacts Android |
| capa | ≥7.0.0 | Apache-2.0 | Analyse statique Mandiant |
| apkid | ≥1.3.5 | GPL-3.0 | Détection packers |
| quark-engine | ≥23.0.0 | Apache-2.0 | Analyse comportementale |
| otxv2 | ≥1.5.0 | BSD-3-Clause | AlienVault OTX |

### Dépendances de développement

| Package | Version | Licence | Usage |
|---------|---------|---------|-------|
| pytest | ≥8.0 | MIT | Framework de tests |
| ruff | ≥0.8 | MIT | Linting |
| mypy | ≥1.13 | MIT | Type checking |
| pyinstaller | ≥6.0 | GPL-2.0 | Packaging Windows |

### Dépendances indirectes notables

| Package | Licence | Transmis via |
|---------|---------|-------------|
| certifi | MPL-2.0 | requests |
| charset-normalizer | MIT | requests |
| urllib3 | MIT | requests |
| setuptools | MIT | pyinstaller |
| pefile | MIT | pyinstaller |
| altgraph | BSD | pyinstaller |

## Notices MVT (Mobile Verification Toolkit)

MVT est développé par Amnesty International et distribué sous MPL-2.0.
Utilisé pour la détection de spywares mobiles (Pegasus, Predator, FinSpy).

https://github.com/mvt-project/mvt

## Notices ALEAPP

ALEAPP (Android Logs Events And Protobuf Parser) est distribué sous Apache-2.0.
Utilisé pour le parsing profond des artefacts Android.

https://github.com/abrignoni/ALEAPP

## Notices Capa

Capa est développé par Mandiant/Google et distribué sous Apache-2.0.
Utilisé pour l'analyse statique des capacités malveillantes.

https://github.com/mandiant/capa

## Notices APKiD

APKiD est développé par RedNaga et distribué sous GPL-3.0.
Utilisé pour la détection de packers et d'obfuscation.

https://github.com/rednaga/APKiD

## Notices Quark-Engine

Quark-Engine est distribué sous Apache-2.0.
Utilisé pour l'analyse comportementale du bytecode Dalvik.

https://github.com/quark-engine/quark-engine

## Notices YARA

Les règles YARA du projet sont basées sur :
- Règles personnalisées (Custom)
- Règles MVT/Amnesty International (MPL-2.0)
- Règles yara-rules community (MIT)

Les règles YARA sont fournies "telles quelles" sans garantie.

## Avertissement

Cet outil est fourni à des fins d'analyse forensique légale. L'utilisation doit
respecter les lois applicables en matière de privacy, de surveillance et de
collecte de preuves numériques. Les auteurs déclinent toute responsabilité pour
une utilisation abusive de cet outil.
