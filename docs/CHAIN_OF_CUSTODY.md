# Chain of custody

Each scan must record case ID, scan ID, source platform, original source path,
working-copy path, acquisition method and command, exit code, UTC start/end,
size, SHA-256, tool/application versions, warnings, errors and limitations.

Original evidence is read-only where possible. Derived files are stored outside
the original evidence directory. Custody entries are serialized and linked by
hash or signature. Verification re-hashes every evidence file and validates
ledger order and linkage.
