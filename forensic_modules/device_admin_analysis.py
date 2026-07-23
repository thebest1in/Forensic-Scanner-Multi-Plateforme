"""Device admin analysis — enterprise policy abuse detection."""

SYSTEM_ADMIN_PREFIXES = (
    "com.android.", "com.google.", "com.samsung.", "com.xiaomi.",
    "com.huawei.", "com.qualcomm.", "com.mediatek.",
)


def check_device_admin(content: str, source_file: str) -> list[dict]:
    """Parse dumpsys device_policy output for admin abuse indicators."""
    findings = []
    admins = []
    policies = {}

    for line in content.splitlines():
        line = line.strip()
        if "No admins" in line:
            return findings

        if "Active admin #" in line or "Device Owner:" in line or "Profile Owner:" in line:
            parts = line.split(":", 1) if ":" in line else line.split("#", 1)
            if len(parts) == 2:
                admin_name = parts[1].strip()
                if admin_name and admin_name != "(none)":
                    admins.append(admin_name)

        for prop in ("mPasswordQuality", "mCameraDisabled", "mKeyguardDisabled",
                      "mPermittedAccessibilityServices", "mPermittedNotificationListeners"):
            if prop in line and "=" in line:
                val = line.split("=", 1)[-1].strip()
                policies[prop] = val

    for admin in admins:
        is_system = any(admin.startswith(p) for p in SYSTEM_ADMIN_PREFIXES)
        if not is_system:
            findings.append({
                "type": "DEVICE_ADMIN_ABUSE",
                "severity": "HIGH",
                "admin": admin,
                "evidence": f"Non-system device administrator active: {admin}",
                "file": source_file,
            })

    camera_disabled = policies.get("mCameraDisabled", "")
    if camera_disabled == "true":
        findings.append({
            "type": "POLICY_RESTRICTION",
            "severity": "MEDIUM",
            "policy": "mCameraDisabled",
            "evidence": "Camera has been disabled by device admin policy",
            "file": source_file,
        })

    keyguard_disabled = policies.get("mKeyguardDisabled", "")
    if keyguard_disabled == "true":
        findings.append({
            "type": "POLICY_RESTRICTION",
            "severity": "HIGH",
            "policy": "mKeyguardDisabled",
            "evidence": "Keyguard/lock screen has been disabled by device admin",
            "file": source_file,
        })

    permitted_accessibility = policies.get("mPermittedAccessibilityServices", "")
    if permitted_accessibility and permitted_accessibility != "null":
        findings.append({
            "type": "ADMIN_POLICY",
            "severity": "INFO",
            "policy": "mPermittedAccessibilityServices",
            "evidence": f"Admin restricts accessibility services: {permitted_accessibility[:100]}",
            "file": source_file,
        })

    permitted_notifications = policies.get("mPermittedNotificationListeners", "")
    if permitted_notifications and permitted_notifications != "null":
        findings.append({
            "type": "ADMIN_POLICY",
            "severity": "INFO",
            "policy": "mPermittedNotificationListeners",
            "evidence": f"Admin restricts notification listeners: {permitted_notifications[:100]}",
            "file": source_file,
        })

    if policies and not admins:
        findings.append({
            "type": "ADMIN_POLICY",
            "severity": "INFO",
            "evidence": "Device policies active but no admin identified",
            "file": source_file,
            "policies": list(policies.keys()),
        })

    return findings
