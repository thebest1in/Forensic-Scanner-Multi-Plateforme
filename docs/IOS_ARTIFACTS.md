# iOS profile and artifact matrix

| Profile | Live USB | Offline backup | Typical coverage |
|---|---:|---:|---|
| triage | device information | metadata, applications | basic identification |
| deep | live metadata where exposed | profiles, domains, analytics, crash data | expanded logical analysis |
| forensic | live metadata only without backup | all supported parsers, MVT bridge when configured | maximum available coverage |

Backup-only records such as SMS, calls, Safari and application domains must be
marked `BACKUP_REQUIRED` when no local backup is available.
