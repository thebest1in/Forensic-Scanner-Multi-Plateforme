"""Dangerous permission correlation — detect suspicious permission combinations."""

CRITICAL_PERMISSIONS = {
    "RECEIVE_SMS", "READ_SMS", "SEND_SMS", "RECORD_AUDIO",
    "CAMERA", "READ_CONTACTS", "READ_CALL_LOG", "ACCESS_FINE_LOCATION",
    "ACCESS_COARSE_LOCATION", "SYSTEM_ALERT_WINDOW", "DEVICE_ADMIN",
    "INSTALL_PACKAGES", "DELETE_PACKAGES", "MANAGE_EXTERNAL_STORAGE",
    "READ_PHONE_STATE", "CALL_PHONE", "WRITE_SMS", "WRITE_CALL_LOG",
}

SUSPICIOUS_COMBOS = [
    {
        "name": "Stalkerware Profile",
        "permissions": {"RECEIVE_SMS", "RECORD_AUDIO", "SYSTEM_ALERT_WINDOW"},
        "severity": "CRITICAL",
        "description": "SMS interception + silent recording + overlay = classic stalkerware",
    },
    {
        "name": "Surveillance Suite",
        "permissions": {"CAMERA", "RECORD_AUDIO", "READ_SMS", "ACCESS_FINE_LOCATION"},
        "severity": "CRITICAL",
        "description": "Full surveillance: camera, mic, SMS, and location",
    },
    {
        "name": "Data Theft",
        "permissions": {"READ_CONTACTS", "ACCESS_FINE_LOCATION", "CAMERA"},
        "severity": "HIGH",
        "description": "Contacts + location + camera = exfiltration capability",
    },
    {
        "name": "Communication Theft",
        "permissions": {"READ_CALL_LOG", "READ_SMS", "READ_CONTACTS"},
        "severity": "HIGH",
        "description": "Full communication history access",
    },
    {
        "name": "Silent Recording",
        "permissions": {"RECORD_AUDIO", "FOREGROUND_SERVICE", "WAKE_LOCK"},
        "severity": "HIGH",
        "description": "Background audio recording capability",
    },
    {
        "name": "Device Takeover",
        "permissions": {"DEVICE_ADMIN", "INSTALL_PACKAGES", "SYSTEM_ALERT_WINDOW"},
        "severity": "CRITICAL",
        "description": "Admin + package install + overlay = full device control",
    },
    {
        "name": "Location Tracking",
        "permissions": {"ACCESS_FINE_LOCATION", "RECEIVE_BOOT_COMPLETED", "FOREGROUND_SERVICE"},
        "severity": "MEDIUM",
        "description": "Persistent location tracking after reboot",
    },
    {
        "name": "Accessibility Device Takeover",
        "permissions": {"BIND_DEVICE_ADMIN", "INSTALL_PACKAGES", "BIND_ACCESSIBILITY_SERVICE"},
        "severity": "CRITICAL",
        "description": "Device admin + package install + accessibility service = full UI control and silent install capability",
    },
]


def check_permission_combinations(content: str, source_file: str) -> list[dict]:
    """Parse permission grant data and detect suspicious combinations."""
    findings = []
    package_permissions = {}
    current_pkg = ""

    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("package:") or (not line.startswith(" ") and "=" not in line and len(line) > 3):
            current_pkg = line.split(":", 1)[-1].strip() if ":" in line else line.strip()
            if current_pkg not in package_permissions:
                package_permissions[current_pkg] = set()
        elif current_pkg and any(p in line for p in CRITICAL_PERMISSIONS):
            for perm in CRITICAL_PERMISSIONS:
                if perm in line:
                    package_permissions[current_pkg].add(perm)

    for pkg, perms in package_permissions.items():
        if not perms:
            continue
        for combo in SUSPICIOUS_COMBOS:
            if combo["permissions"].issubset(perms):
                findings.append({
                    "type": "DANGEROUS_COMBO",
                    "severity": combo["severity"],
                    "package": pkg,
                    "combo_name": combo["name"],
                    "matched_permissions": sorted(combo["permissions"]),
                    "all_permissions": sorted(perms),
                    "evidence": f"{combo['name']} detected in {pkg}: {combo['description']}",
                    "file": source_file,
                })

        crit_count = len(perms & CRITICAL_PERMISSIONS)
        if crit_count >= 5:
            findings.append({
                "type": "EXCESSIVE_PERMISSIONS",
                "severity": "HIGH",
                "package": pkg,
                "critical_permission_count": crit_count,
                "permissions": sorted(perms & CRITICAL_PERMISSIONS),
                "evidence": f"Package {pkg} holds {crit_count} critical permissions",
                "file": source_file,
            })

    return findings
