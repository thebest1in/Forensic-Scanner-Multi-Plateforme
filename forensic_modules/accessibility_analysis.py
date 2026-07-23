"""Accessibility services analysis — spyware injection vector detection."""

SYSTEM_PACKAGES = {
    "com.google.", "com.android.", "com.samsung.", "com.xiaomi.",
    "com.qualcomm.", "com.mediatek.", "com.huawei.", "com.oneplus.",
}

KNOWN_LEGITIMATE = {
    "com.google.android.marvin.talkback",
    "com.google.android.accessibility.selecttospeak",
    "com.google.android.accessibility.braille",
    "com.samsung.android.app.talkback",
    "com.samsung.android.accessibility.triangle",
}


def check_accessibility_services(content: str, source_file: str) -> list[dict]:
    """Parse accessibility service output and flag non-system services."""
    findings = []
    services = []

    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue

        if "/" in line and ("ServiceInfo" in line or "accessibility" in line.lower()):
            pkg = line.split("/")[0].strip()
            svc = line.strip()
            services.append({"package": pkg, "service": svc})
        elif ":" in line and any(kw in line.lower() for kw in ("enabled", "service", "accessibility")):
            parts = line.split(":", 1)
            if len(parts) == 2:
                for svc in parts[1].split(":"):
                    svc = svc.strip()
                    if "/" in svc:
                        pkg = svc.split("/")[0].strip()
                        services.append({"package": pkg, "service": svc})

    if not services and content.strip() and content.strip() not in ("{}", "Bound services:{}", "installedServiceCount=0"):
        for line in content.splitlines():
            line = line.strip()
            if "/" in line:
                pkg = line.split("/")[0].strip()
                if pkg:
                    services.append({"package": pkg, "service": line})

    for svc_info in services:
        pkg = svc_info["package"]
        is_system = any(pkg.startswith(sys_pkg) for sys_pkg in SYSTEM_PACKAGES)
        is_known_legit = pkg in KNOWN_LEGITIMATE

        if not is_system and not is_known_legit:
            findings.append({
                "type": "ACCESSIBILITY_ABUSE",
                "severity": "HIGH",
                "package": pkg,
                "service": svc_info["service"],
                "evidence": f"Non-system accessibility service active: {pkg}",
                "file": source_file,
            })

    if not services and content.strip() and content.strip() not in ("{}", "Bound services:{}", ""):
        findings.append({
            "type": "ACCESSIBILITY_INFO",
            "severity": "INFO",
            "evidence": "Accessibility services data present but unparseable — manual review recommended",
            "file": source_file,
        })

    return findings
