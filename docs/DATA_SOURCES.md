# Data sources and provenance

This file records the origin, version, license and retrieval metadata for
external intelligence and reference data. A release must replace every
`RECORD_REQUIRED` value with a measured value and SHA-256.

| Source | Data | Version/date | License | Use |
|---|---|---|---|---|
| MVT | iOS/Android IOC checks | 2026.5.12 installed | MVT project license | IOC corroboration |
| MITRE ATT&CK Mobile | Android/iOS techniques | RECORD_REQUIRED | MITRE terms | behavioral mapping |
| Internal YARA | local signatures | Git commit required | project license | local detection |
| IP feed | 25,954 normalized IPs | file `rules/known_ips.txt` | mixed sources; exact provider/date unknown | network correlation |
| Apple allowlist | Apple identifiers | iOS-version scoped | documented source required | false-positive reduction |

## Required feed manifest

```json
{
  "source": "provider",
  "source_type": "ip_blocklist",
  "retrieved_at_utc": "RECORD_REQUIRED",
  "license": "RECORD_REQUIRED",
  "original_count": 0,
  "normalized_count": 25954,
  "sha256": "RECORD_REQUIRED",
  "expiration_policy_days": 30
}
```

Confirmed local metadata for `rules/known_ips.txt`:

```text
Header: Source: abuse.ch, AbuseIPDB, known spyware infrastructure
Normalized count: 25,954 (runtime log)
File size: 396,904 bytes at validation
SHA-256: E83AA34545550D995A912B4DF96E1FBB59128D6C596F50C06255256D3004686C
Exact feed/date/license: not yet verifiable from repository metadata
```

The header identifies mixed origins, not a single authoritative provider. Do
not attribute the dataset to one provider until its retrieval manifest exists.

Official references: [MVT IOC documentation](https://docs.mvt.re/en/latest/iocs/),
[MVT backup methodology](https://docs.mvt.re/en/latest/ios/methodology/),
[MITRE Mobile techniques](https://attack.mitre.org/techniques/mobile/).
