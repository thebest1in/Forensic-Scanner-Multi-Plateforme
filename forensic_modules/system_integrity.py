"""System integrity verification — security properties, secure boot, odsign."""



def check_system_properties(content: str, source_file: str) -> list[dict]:
    """Parse system_properties.txt and verify all critical security flags."""
    findings = []
    props = {}
    for line in content.splitlines():
        line = line.strip()
        if "=" in line:
            key, _, val = line.partition("=")
            key = key.strip()
            val = val.strip()
            if key and val:
                props[key] = val

    checks = [
        ("ro.debuggable", "0", "CRITICAL", "Device is in debuggable mode"),
        ("ro.secure", "1", "CRITICAL", "ro.secure is not 1 — ADB may have root access"),
        ("ro.build.type", "user", "HIGH", "Non-user build type detected (eng/userdebug)"),
        ("ro.adb.secure", "1", "HIGH", "ADB authentication is disabled"),
        ("ro.boot.secureboot", "1", "HIGH", "Secure boot is not enabled"),
        ("ro.secureboot.lockstate", "locked", "HIGH", "Bootloader is unlocked"),
        ("odsign.verification.success", "1", "CRITICAL", "OD signature verification failed"),
    ]

    for prop, expected, severity, message in checks:
        actual = props.get(prop, "")
        if actual and actual != expected:
            findings.append({
                "type": "SYSTEM_INTEGRITY",
                "severity": severity,
                "property": prop,
                "expected": expected,
                "actual": actual,
                "evidence": f"{message} ({prop}={actual}, expected={expected})",
                "file": source_file,
            })

    if not props:
        findings.append({
            "type": "SYSTEM_INTEGRITY",
            "severity": "MEDIUM",
            "evidence": "System properties file is empty or unparseable",
            "file": source_file,
        })

    return findings
