# Forensic limitations and interpretation policy

`CLEAN` means no authoritative malicious evidence was identified by the
analyses that actually ran. It never proves that a device is malware-free.

## iOS acquisition states

```text
SUCCESS
FAILED
EMPTY
NOT_SUPPORTED
PROTECTED_BY_IOS
BACKUP_REQUIRED
DEVICE_LOCKED
PRESENT_BUT_ENCRYPTED
PRESENT_BUT_UNRESOLVED
PARSER_PATH_NOT_SUPPORTED
```

iOS Live Lockdown provides device metadata and selected services. It does not
provide all SMS, Safari, call, contact, sandbox, or encrypted application data.
Those artifacts require a valid local backup or a supported privileged source.

## iOS backup parser reporting

Every parser should record database presence, SHA-256, detected schema,
supported schema, rows available, rows parsed, rows rejected, and failure
reason. `NOT_FOUND` must distinguish absent-in-manifest from unresolved fileID.

## Timeline interpretation

Timeline counts must distinguish `DEVICE_ACTIVITY`, `SCANNER_ACTIVITY`,
`DETECTION`, `TOOL_EXECUTION`, and `REMEDIATION`. A count of 35 must not be
described as 35 device events unless the event sources prove that distinction.
