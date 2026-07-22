"""APK signature verification — parse pm verify output, detect tampered apps."""

SUSPICIOUS_PACKAGES = {
    "com.anydesk.anydeskandroid": "remote_access",
    "com.teamviewer.teamviewer": "remote_access",
    "com.logmein.rescue": "remote_access",
}


def check_apk_signatures(content: str, source_file: str) -> list[dict]:
    """Parse pm verify output and flag verification failures."""
    findings = []
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        if "verification failure" in line.lower() or "not verified" in line.lower():
            pkg = line.split()[0] if line.split() else "unknown"
            findings.append({
                "type": "SIGNATURE_FAILURE",
                "severity": "CRITICAL",
                "package": pkg,
                "evidence": f"APK signature verification failed: {line}",
                "file": source_file,
            })
        elif "not signed" in line.lower():
            pkg = line.split()[0] if line.split() else "unknown"
            findings.append({
                "type": "UNSIGNED_APK",
                "severity": "HIGH",
                "package": pkg,
                "evidence": f"APK is not signed: {line}",
                "file": source_file,
            })
        elif "verified" in line.lower() and "not" not in line.lower():
            for pkg, category in SUSPICIOUS_PACKAGES.items():
                if pkg in line.lower():
                    findings.append({
                        "type": "DUAL_USE_APP_VERIFIED",
                        "severity": "INFO",
                        "package": pkg,
                        "category": category,
                        "evidence": f"Dual-use app signature verified: {pkg}",
                        "file": source_file,
                    })

    return findings
