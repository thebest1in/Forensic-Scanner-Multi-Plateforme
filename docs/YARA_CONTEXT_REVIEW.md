# YARA Context Review — bugreport-poco.zip

Review date: 2026-07-22 UTC

## Scope and reproducibility

The reviewed artifact is the 184,850,385-byte aggregate Android bugreport
`bugreport-duchamp_eea-BP2A.250605.031.A3-2026-07-20-17-17-15.txt` extracted
from `bugreport-poco.zip`. The complete pre-change string evidence is stored in
`diagnostics/yara_before.json`; the post-rule evidence is stored in
`diagnostics/yara_after_rules.json`. Records include namespace, tags, string
identifier, byte offset, matched preview, adjacent context, and artifact type.

## Match assessment

| Rule | Representative evidence | Assessment | Reason |
|---|---|---|---|
| `Disguised_Suspicious_Package` | `$pkg2` `com.mspy.lite` at 116196520 | Likely false positive (0.05) | The name is one entry in a parental-control/security reference list; there is no package installation record and the archive contains zero third-party packages. |
| `Suspicious_Battery_Consumption` | `$b1` `WAKE_LOCK` at 2185690 | Generic diagnostic text (0.10) | The excerpt is a normal `PowerManagerService` record for Google Play Services/LinkedIn. The rule combined common terms across unrelated sections of a 184 MB aggregate file. |
| `Suspicious_Network_Patterns` | `$n1` `ESTABLISHED` at 53111370 | Likely false positive | The old rule combined an iptables state token with `value:9999` elsewhere in the file. The latter was configuration data, not an IP endpoint. The corrected rule no longer matches this artifact. |
| `Android_Credential_Harvester` | `$c1` `getPassword` at 21820273 | Generic diagnostic text (0.10) | The actual token is the prefix of framework setting name `getPasswordTypes`; permission inventories elsewhere supplied the remaining generic strings. |
| `Android_Data_Exfiltration` | `$e1` `Upload` at 577852 | Generic diagnostic text (0.05) | This occurrence is part of a normal thread name. Other terms such as `POST`, `multipart`, `.zip`, and `tar` occur in unrelated diagnostics and archive metadata. |
| `Android_Root_Detection_Evasion` | `$r2` `ro.debuggable` at 19240350 | Likely false positive (0.05) | The excerpt says access to the property was denied. Other matches include path prefixes such as `/system/bin/su` in `/system/bin/surfaceflinger` and security watchlists. |

All records use YARA namespace `default`. These conclusions apply to this
aggregate bugreport context. The same rules can remain authoritative on focused
artifacts such as an APK or package inventory, where supporting context is not
silently discarded.

## Policy change

Raw matches are retained in JSON and reports. Each match now carries an explicit
classification, confidence, reason, and `authoritative` flag. Aggregate
bugreport text cannot independently escalate the verdict unless rule-specific
context proves the intended fact. Remediation and correlation ignore only
non-authoritative matches; they do not delete them.

The network rule now requires a real IP address followed by port 4444, 9999, or
31337 on a line that also contains `ESTABLISHED` or `SYN_SENT`. This preserves a
real endpoint signal while excluding unrelated numeric configuration values.

## Before/after

| Metric | Before | After |
|---|---:|---:|
| Raw YARA rules | 6 | 5 |
| Direct/authoritative YARA evidence | 6 (legacy assumption) | 0 |
| Weighted score | 35/100 LOW_RISK | 0/100 CLEAN |
| Verdict | CRITICAL | CLEAN |
| Successful tools | correlation only | entropy, correlation |
| Skipped for no suitable input | ambiguous | browser, intel |
| Unavailable | mixed with failures/skips | ALEAPP |
| Disabled | mixed with failures/skips | MVT, APKiD, capa, Quark |
| End-to-end duration | not baselined | 37.9 seconds |

The verdict changed because the evidence semantics changed, not because a
threshold was lowered. There was no authoritative YARA hit, IOC hit, third-party
package, entropy finding, browser result, or cross-tool correlation in the
post-change run.

## Limitations

- No malware absence claim can be made from this scan: several analyzers were
  disabled, unavailable, or lacked supported inputs.
- An aggregate text bugreport can omit relevant application payloads and private
  data. Context classification reduces false escalation but is not exculpatory.
- GUI offline mode now pauses USB monitoring to avoid the unrelated five-second
  `adb devices -l` probe. The command-line reproduction does not start that
  monitor, so the GUI-specific behavior is covered by a regression test.
