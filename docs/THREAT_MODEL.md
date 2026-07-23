# Operational threat model

Backups contain highly sensitive personal data and may contain credentials,
messages, locations and health information. The scanner must protect them with
restricted filesystem permissions, no secrets in logs, read-only originals,
separate derived output, retention controls and explicit operator consent.

Threats include malicious backup content, path traversal, parser crashes,
command injection through external tools, accidental remediation, and leakage
of backup passwords or reports.
