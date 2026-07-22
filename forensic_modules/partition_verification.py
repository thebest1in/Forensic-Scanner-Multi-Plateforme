"""Partition integrity verification — digest comparison, tampering detection."""



REQUIRED_PARTITIONS = [
    "system", "vendor", "product", "odm", "system_ext",
    "vendor_dlkm", "odm_dlkm", "system_dlkm", "mi_ext",
]


def check_partition_integrity(content: str, source_file: str) -> list[dict]:
    """Parse partition_integrity.txt and verify digest presence and format."""
    findings = []
    digests = {}
    for line in content.splitlines():
        line = line.strip()
        if "=" in line:
            key, _, val = line.partition("=")
            key = key.strip().replace("partition.", "").replace(".verified.root_digest", "")
            val = val.strip()
            if key and val:
                digests[key] = val

    missing = [p for p in REQUIRED_PARTITIONS if p not in digests]
    if missing:
        findings.append({
            "type": "PARTITION_INTEGRITY",
            "severity": "MEDIUM",
            "evidence": f"Missing partition digests: {', '.join(missing)}",
            "missing_partitions": missing,
            "file": source_file,
        })

    for partition, digest in digests.items():
        if not digest or digest in ("", "(unknown)", "error", "not found"):
            findings.append({
                "type": "PARTITION_TAMPERING",
                "severity": "CRITICAL",
                "partition": partition,
                "evidence": f"Partition '{partition}' has no valid integrity digest",
                "file": source_file,
            })
        elif len(digest) < 16:
            findings.append({
                "type": "PARTITION_TAMPERING",
                "severity": "HIGH",
                "partition": partition,
                "evidence": f"Partition '{partition}' digest too short: {digest[:20]}",
                "file": source_file,
            })

    if not digests:
        findings.append({
            "type": "PARTITION_INTEGRITY",
            "severity": "MEDIUM",
            "evidence": "No partition digests found — file may be empty",
            "file": source_file,
        })

    return findings
