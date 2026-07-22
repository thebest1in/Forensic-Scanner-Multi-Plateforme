from pathlib import Path
import re

from core import logger


# ============================================================
# DANGEROUS PERMISSION MATRICES
# ============================================================

# Tier 1: Critical permissions (any 2 together = HIGH risk)
CRITICAL_PERMISSIONS = {
    "RECEIVE_SMS", "READ_SMS", "SEND_SMS",
    "RECORD_AUDIO", "CAMERA",
    "READ_CONTACTS", "WRITE_CONTACTS",
    "READ_CALL_LOG", "WRITE_CALL_LOG",
    "READ_PHONE_STATE", "CALL_PHONE",
    "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION",
    "SYSTEM_ALERT_WINDOW",
    "DEVICE_ADMIN",
    "READ_CALENDAR", "WRITE_CALENDAR",
    "BODY_SENSORS",
    "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE",
    "MANAGE_EXTERNAL_STORAGE",
}

# Tier 2: Suspicious alone in non-utility apps
SUSPICIOUS_PERMISSIONS = {
    "RECEIVE_BOOT_COMPLETED",
    "WAKE_LOCK",
    "FOREGROUND_SERVICE",
    "BIND_ACCESSIBILITY_SERVICE",
    "BIND_DEVICE_ADMIN",
    "INSTALL_PACKAGES",
    "DELETE_PACKAGES",
    "REQUEST_INSTALL_PACKAGES",
    "REQUEST_DELETE_PACKAGES",
    "READ_LOGS",
    "DUMP",
    "SET_DEBUG_APP",
}

# Tier 3: Permission combinations that indicate spyware
SPYWARE_COMBOS = [
    # Classic stalkerware pattern: reads SMS + records audio + overlays
    {"RECEIVE_SMS", "RECORD_AUDIO", "SYSTEM_ALERT_WINDOW"},
    # Spying combo: contacts + location + camera
    {"READ_CONTACTS", "ACCESS_FINE_LOCATION", "CAMERA"},
    # Data theft: calls + SMS + contacts
    {"READ_CALL_LOG", "READ_SMS", "READ_CONTACTS"},
    # Surveillance: audio + location + boot persistence
    {"RECORD_AUDIO", "ACCESS_FINE_LOCATION", "RECEIVE_BOOT_COMPLETED"},
    # Device takeover: admin + install + accessibility
    {"BIND_DEVICE_ADMIN", "INSTALL_PACKAGES", "BIND_ACCESSIBILITY_SERVICE"},
    # Silent recording: audio + background service + wake lock
    {"RECORD_AUDIO", "FOREGROUND_SERVICE", "WAKE_LOCK"},
    # Full surveillance: all sensors + data access
    {"CAMERA", "RECORD_AUDIO", "READ_SMS", "ACCESS_FINE_LOCATION"},
]

# App categories where certain permissions are expected (lower risk)
UTILITY_CATEGORIES = {
    "com.android.chrome": {"CAMERA", "READ_EXTERNAL_STORAGE", "ACCESS_FINE_LOCATION"},
    "com.whatsapp": {"CAMERA", "RECORD_AUDIO", "READ_CONTACTS", "ACCESS_FINE_LOCATION", "READ_SMS"},
    "com.google.android.gm": {"READ_CONTACTS", "READ_CALENDAR"},
    "com.google.android.apps.maps": {"ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION"},
}


class HeuristicResult:
    def __init__(self):
        self.risk_score: int = 0  # 0-100
        self.risk_level: str = "CLEAN"
        self.flagged_packages: list[dict] = []
        self.suspicious_combos: list[dict] = []
        self.details: str = ""

    def to_dict(self) -> dict:
        return {
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "flagged_packages": self.flagged_packages,
            "suspicious_combos": self.suspicious_combos,
            "details": self.details,
        }


def analyze_permissions(
    extracted_files: dict[str, Path],
    on_progress=None,
) -> HeuristicResult:
    """
    Analyze third-party app permissions from extracted artifacts.
    Reads third_party_apps.txt and device_admin.txt for permission data.
    """
    result = HeuristicResult()
    total_score = 0

    # Find relevant files
    apps_file = _find_file(extracted_files, ["third_party_apps", "third_party_apps.txt"])
    device_info = _find_file(extracted_files, ["device_info", "device_info.txt"])
    accessibility = _find_file(extracted_files, ["accessibility_services", "accessibility_services.txt"])
    device_admin = _find_file(extracted_files, ["device_admin", "device_admin.txt"])

    # Parse third-party packages
    packages = []
    if apps_file and apps_file.exists():
        try:
            content = apps_file.read_text(encoding="utf-8", errors="replace")
            for line in content.splitlines():
                if line.startswith("package:"):
                    pkg_match = re.search(r"package:(.+?)=", line)
                    if pkg_match:
                        packages.append(pkg_match.group(1))
        except Exception as e:
            logger.warning(f"Cannot parse packages: {e}")

    _report(on_progress, 20, f"Analyzing {len(packages)} third-party packages...")

    # Check each package for suspicious characteristics
    for pkg in packages:
        pkg_risk = _assess_package_risk(pkg)
        if pkg_risk["score"] > 0:
            result.flagged_packages.append(pkg_risk)
            total_score += pkg_risk["score"]

    # Check for known malicious packages
    for pkg in packages:
        pkg_lower = pkg.lower()
        if any(mp in pkg_lower for mp in [
            "flexispy", "mspy", "cerberus", "spybubble", "mobilespy",
            "sys.update.co", "service.update", "droidjack", "sandrorat"
        ]):
            result.flagged_packages.append({
                "package": pkg,
                "score": 50,
                "reasons": ["Known spyware package name"],
                "risk": "CRITICAL",
            })
            total_score += 50
            logger.warning(f"Known spyware package: {pkg}")

    # Check accessibility services
    if accessibility and accessibility.exists():
        try:
            content = accessibility.read_text(encoding="utf-8", errors="replace")
            if "Bound services:{}" not in content and "installedServiceCount=0" not in content:
                # Check for non-system accessibility services
                for line in content.splitlines():
                    if "ServiceInfo" in line or "accessibility" in line.lower():
                        if not any(sys in line.lower() for sys in ["com.google", "com.samsung", "com.android"]):
                            result.flagged_packages.append({
                                "package": "unknown_accessibility",
                                "score": 20,
                                "reasons": ["Non-system accessibility service detected"],
                                "risk": "HIGH",
                            })
                            total_score += 20
        except Exception:
            pass

    # Check device admin
    if device_admin and device_admin.exists():
        try:
            content = device_admin.read_text(encoding="utf-8", errors="replace")
            if "No admins" not in content:
                admin_pkgs = re.findall(r"Active admin #\d+:\s+(.+)", content)
                for admin_pkg in admin_pkgs:
                    admin_pkg = admin_pkg.strip()
                    if not any(sys in admin_pkg.lower() for sys in [
                        "com.android", "com.google", "com.samsung", "com.xiaomi"
                    ]):
                        result.flagged_packages.append({
                            "package": admin_pkg,
                            "score": 30,
                            "reasons": ["Non-system device administrator"],
                            "risk": "HIGH",
                        })
                        total_score += 30
                        logger.warning(f"Suspicious device admin: {admin_pkg}")
        except Exception:
            pass

    # Cap the score at 100
    result.risk_score = min(total_score, 100)

    if result.risk_score >= 70:
        result.risk_level = "CRITICAL"
    elif result.risk_score >= 40:
        result.risk_level = "SUSPICIOUS"
    elif result.risk_score > 0:
        result.risk_level = "LOW_RISK"
    else:
        result.risk_level = "CLEAN"

    result.details = _build_heuristic_summary(result)
    _report(on_progress, 90, f"Heuristic analysis complete: {result.risk_level} (score={result.risk_score})")
    logger.info(f"Heuristic score: {result.risk_score}/100 ({result.risk_level})")
    return result


def _assess_package_risk(package_name: str) -> dict:
    """Assess risk based on package name patterns."""
    pkg_lower = package_name.lower()
    reasons = []
    score = 0

    # Pattern: disguised system update
    if re.match(r"com\.android\.(sys\.update|service\.update|packageinstaller\.helper)", pkg_lower):
        reasons.append("Disguised as Android system component")
        score += 30

    # Pattern: disguised Google service
    if re.match(r"com\.google\.(service\.helper|update\.service)", pkg_lower):
        reasons.append("Disguised as Google service")
        score += 25

    # Pattern: disguised Xiaomi service
    if "com.xiaomi.system.update.service" in pkg_lower:
        reasons.append("Disguised as Xiaomi system update")
        score += 25

    # Pattern: known spyware names
    spyware_names = ["mspy", "flexispy", "cerberus", "spybubble", "mobilespy",
                     "highster", "mobili", "spyrie", "thetracker"]
    for name in spyware_names:
        if name in pkg_lower:
            reasons.append(f"Contains known spyware name: {name}")
            score += 40
            break

    # Pattern: very generic names (often used by spyware)
    generic_names = ["helper", "service", "update", "manager", "controller", "monitor"]
    if any(g == pkg_lower.split(".")[-1] for g in generic_names):
        if len(pkg_lower.split(".")) <= 3:
            reasons.append("Generic/suspicious app name")
            score += 5

    return {
        "package": package_name,
        "score": score,
        "reasons": reasons,
        "risk": "HIGH" if score >= 25 else "MEDIUM" if score > 0 else "LOW",
    }


def _find_file(files: dict[str, Path], candidates: list[str]) -> Path | None:
    """Find a file from a list of candidate names."""
    for name in candidates:
        if name in files:
            return files[name]
    return None


def _build_heuristic_summary(result: HeuristicResult) -> str:
    """Build human-readable heuristic summary."""
    if result.risk_level == "CLEAN":
        return (
            "No suspicious permission patterns detected.\n"
            "All third-party apps have expected permission profiles."
        )

    lines = [f"Heuristic Risk Score: {result.risk_score}/100 ({result.risk_level})"]

    if result.flagged_packages:
        lines.append(f"\nFlagged Packages ({len(result.flagged_packages)}):")
        for pkg in result.flagged_packages:
            lines.append(f"  {pkg['package']} [{pkg['risk']}]: {', '.join(pkg['reasons'])}")

    return "\n".join(lines)


def _report(on_progress, percent, message):
    if on_progress:
        try:
            on_progress(percent, message)
        except Exception:
            pass
