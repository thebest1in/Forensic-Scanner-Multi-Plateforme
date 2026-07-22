from __future__ import annotations

from core import logger

# ============================================================
# RECOMMENDATION PRIORITIES
# ============================================================

PRIORITY_HIGH = "HIGH"
PRIORITY_MEDIUM = "MEDIUM"
PRIORITY_LOW = "LOW"

PRIORITY_ORDER = {PRIORITY_HIGH: 0, PRIORITY_MEDIUM: 1, PRIORITY_LOW: 2}

PRIORITY_COLORS = {
    PRIORITY_HIGH: "#e74c3c",
    PRIORITY_MEDIUM: "#f39c12",
    PRIORITY_LOW: "#3498db",
}

PRIORITY_ICONS = {
    PRIORITY_HIGH: "!!!",
    PRIORITY_MEDIUM: "!",
    PRIORITY_LOW: "i",
}


# ============================================================
# RECOMMENDATION TYPES
# ============================================================

TYPE_UNINSTALL = "UNINSTALL"
TYPE_REVOKE = "REVOKE_PERMISSIONS"
TYPE_UPDATE = "UPDATE"
TYPE_ENABLE = "ENABLE_FEATURE"
TYPE_REVIEW = "MANUAL_REVIEW"
TYPE_INFO = "INFORMATIONAL"

TYPE_LABELS = {
    TYPE_UNINSTALL: "Uninstall App",
    TYPE_REVOKE: "Revoke Permissions",
    TYPE_UPDATE: "Update App",
    TYPE_ENABLE: "Enable Security Feature",
    TYPE_REVIEW: "Manual Review Required",
    TYPE_INFO: "Informational",
}


# ============================================================
# HIGH-RISK APP DATABASE
# ============================================================

HIGH_RISK_APPS = {
    "com.anydesk.anydeskandroid": {
        "name": "AnyDesk",
        "risk": "Remote access tool with clipboard and screen access",
        "action": TYPE_UNINSTALL,
        "priority": PRIORITY_HIGH,
        "reason": "Remote access tool with clipboard access — remove if unused",
        "adb_command": "adb uninstall com.anydesk.anydeskandroid",
    },
    "com.nainfomatics.microphone.earspy": {
        "name": "Ear Spy",
        "risk": "Microphone amplifier — can be used for surveillance",
        "action": TYPE_UNINSTALL,
        "priority": PRIORITY_HIGH,
        "reason": "Microphone amplifier (unnecessary risk) — remove if unused",
        "adb_command": "adb uninstall com.nainfomatics.microphone.earspy",
    },
    "free.vpn.unblock.proxy.turbovpn": {
        "name": "Turbo VPN",
        "risk": "Free VPN — logs and sells traffic data",
        "action": TYPE_UNINSTALL,
        "priority": PRIORITY_MEDIUM,
        "reason": "Free VPNs log and sell traffic data — remove if unused",
        "adb_command": "adb uninstall free.vpn.unblock.proxy.turbovpn",
    },
    "com.naxclow.v720": {
        "name": "V720 Camera",
        "risk": "Chinese IP camera app with location access",
        "action": TYPE_REVIEW,
        "priority": PRIORITY_MEDIUM,
        "reason": "Chinese IP camera app with location access — review usage",
        "adb_command": None,
    },
}

MEDIUM_RISK_APPS = {
    "com.tiqiaa.remote": {
        "name": "Tiqiaa Remote",
        "risk": "Remote control app — potential for unauthorized access",
        "action": TYPE_REVIEW,
        "priority": PRIORITY_LOW,
        "reason": "Remote control app — verify legitimate use",
        "adb_command": None,
    },
    "com.anydesk.anydeskandroid": HIGH_RISK_APPS["com.anydesk.anydeskandroid"],
    "com.nainfomatics.microphone.earspy": HIGH_RISK_APPS["com.nainfomatics.microphone.earspy"],
}


# ============================================================
# RECOMMENDATION RESULT
# ============================================================

class RecommendationResult:
    def __init__(self):
        self.recommendations: list[dict] = []

    def add(self, rec: dict):
        self.recommendations.append(rec)

    def sort(self):
        self.recommendations.sort(
            key=lambda r: PRIORITY_ORDER.get(r.get("priority", PRIORITY_LOW), 99)
        )

    def to_dict(self) -> dict:
        return {
            "total": len(self.recommendations),
            "high_priority": sum(1 for r in self.recommendations if r.get("priority") == PRIORITY_HIGH),
            "medium_priority": sum(1 for r in self.recommendations if r.get("priority") == PRIORITY_MEDIUM),
            "low_priority": sum(1 for r in self.recommendations if r.get("priority") == PRIORITY_LOW),
            "recommendations": self.recommendations,
        }


# ============================================================
# MAIN RECOMMENDATIONS ENGINE
# ============================================================

def generate_recommendations(
    analysis_result,
    remediation_result=None,
    third_party_packages: list[str] | None = None,
    device_info: dict | None = None,
    on_progress=None,
) -> RecommendationResult:
    """
    Generate prioritized recommendations based on scan results.
    Combines automated findings with high-risk app database.
    """
    result = RecommendationResult()

    _report(on_progress, 10, "Checking high-risk applications...")
    _check_high_risk_apps(third_party_packages or [], result)

    _report(on_progress, 30, "Evaluating YARA findings...")
    _recommendations_from_yara(analysis_result, result)

    _report(on_progress, 50, "Evaluating heuristic findings...")
    _recommendations_from_heuristics(analysis_result, result)

    _report(on_progress, 70, "Evaluating remediation actions...")
    _recommendations_from_remediation(remediation_result, result)

    _report(on_progress, 85, "Adding security recommendations...")
    _add_security_recommendations(device_info, result)

    _report(on_progress, 95, "Sorting recommendations...")
    result.sort()

    _report(on_progress, 100, f"Generated {len(result.recommendations)} recommendations.")
    return result


# ============================================================
# CHECK HIGH-RISK APPS
# ============================================================

def _check_high_risk_apps(packages: list[str], result: RecommendationResult):
    """Check installed packages against high-risk app database."""
    for pkg in packages:
        if pkg in HIGH_RISK_APPS:
            app_info = HIGH_RISK_APPS[pkg]
            result.add({
                "type": app_info["action"],
                "priority": app_info["priority"],
                "target": pkg,
                "target_name": app_info["name"],
                "reason": app_info["reason"],
                "risk": app_info["risk"],
                "adb_command": app_info["adb_command"],
                "source": "high_risk_app_database",
            })
            logger.info(f"High-risk app recommendation: {app_info['name']} ({app_info['priority']})")


# ============================================================
# RECOMMENDATIONS FROM YARA
# ============================================================

def _recommendations_from_yara(analysis_result, result: RecommendationResult):
    """Generate recommendations from YARA match findings."""
    if not analysis_result or not hasattr(analysis_result, "matched_rules"):
        return

    for match in analysis_result.matched_rules:
        if not match.get("authoritative", True):
            continue

        rule_name = match.get("rule", "")
        severity = match.get("meta", {}).get("severity", "MEDIUM")
        tags = {t.lower() for t in match.get("tags", [])}
        source_file = match.get("file", "")

        if severity in ("CRITICAL", "HIGH") or tags & {"pegasus", "zero_click", "novispy", "finspy"}:
            result.add({
                "type": TYPE_UNINSTALL,
                "priority": PRIORITY_HIGH,
                "target": rule_name,
                "target_name": f"Malware: {rule_name}",
                "reason": f"Critical malware signature detected: {rule_name}",
                "risk": "Malicious code identified by YARA signature",
                "adb_command": None,
                "source": f"yara:{source_file}",
            })
        elif severity == "MEDIUM" or tags & {"stalkerware", "spyware", "credential_theft"}:
            result.add({
                "type": TYPE_REVIEW,
                "priority": PRIORITY_MEDIUM,
                "target": rule_name,
                "target_name": f"Suspicious: {rule_name}",
                "reason": f"Suspicious pattern detected: {rule_name}",
                "risk": "Potentially unwanted application or behavior",
                "adb_command": None,
                "source": f"yara:{source_file}",
            })


# ============================================================
# RECOMMENDATIONS FROM HEURISTICS
# ============================================================

def _recommendations_from_heuristics(analysis_result, result: RecommendationResult):
    """Generate recommendations from heuristic risk scoring."""
    if not analysis_result or not hasattr(analysis_result, "heuristic_result"):
        return

    hr = analysis_result.heuristic_result
    if not hr:
        return

    for pkg_info in hr.get("flagged_packages", []):
        pkg = pkg_info.get("package", "")
        score = pkg_info.get("score", 0)
        reasons = pkg_info.get("reasons", [])

        if pkg == "unknown_accessibility":
            continue

        if score >= 40:
            result.add({
                "type": TYPE_UNINSTALL,
                "priority": PRIORITY_HIGH,
                "target": pkg,
                "target_name": pkg,
                "reason": f"High risk score ({score}/100): {'; '.join(reasons[:3])}",
                "risk": "Overprivileged application with dangerous permission combinations",
                "adb_command": f"adb uninstall {pkg}",
                "source": "heuristics",
            })
        elif score >= 10:
            result.add({
                "type": TYPE_REVOKE,
                "priority": PRIORITY_MEDIUM,
                "target": pkg,
                "target_name": pkg,
                "reason": f"Elevated risk score ({score}/100): {'; '.join(reasons[:3])}",
                "risk": "Application with excessive permissions",
                "adb_command": None,
                "source": "heuristics",
            })


# ============================================================
# RECOMMENDATIONS FROM REMEDIATION
# ============================================================

def _recommendations_from_remediation(remediation_result, result: RecommendationResult):
    """Convert remediation actions to recommendations."""
    if not remediation_result:
        return

    for action in remediation_result.actions:
        action_type = action.get("action", "")
        target = action.get("target", "")
        reason = action.get("reason", "")
        severity = action.get("severity", "MEDIUM")

        if action_type == "DELETE":
            priority = PRIORITY_HIGH if severity in ("CRITICAL", "HIGH") else PRIORITY_MEDIUM
            result.add({
                "type": TYPE_UNINSTALL,
                "priority": priority,
                "target": target,
                "target_name": target,
                "reason": reason,
                "risk": action.get("evidence", ""),
                "adb_command": action.get("adb_command"),
                "source": "remediation_engine",
            })
        elif action_type == "RESTRICT":
            result.add({
                "type": TYPE_REVOKE,
                "priority": PRIORITY_MEDIUM,
                "target": target,
                "target_name": target,
                "reason": reason,
                "risk": action.get("evidence", ""),
                "adb_command": action.get("adb_command"),
                "source": "remediation_engine",
            })
        elif action_type == "UPDATE":
            result.add({
                "type": TYPE_UPDATE,
                "priority": PRIORITY_LOW,
                "target": target,
                "target_name": target,
                "reason": reason,
                "risk": action.get("evidence", ""),
                "adb_command": None,
                "source": "remediation_engine",
            })


# ============================================================
# SECURITY RECOMMENDATIONS
# ============================================================

def _add_security_recommendations(device_info: dict | None, result: RecommendationResult):
    """Add general security recommendations based on device state."""
    if not device_info:
        return

    android_version = device_info.get("android_version", "")
    if android_version and android_version.startswith("1"):
        try:
            major = int(android_version.split(".")[0])
            if major < 14:
                result.add({
                    "type": TYPE_ENABLE,
                    "priority": PRIORITY_LOW,
                    "target": "system_update",
                    "target_name": "Android System Update",
                    "reason": f"Android {android_version} is outdated — update to latest version",
                    "risk": "Outdated OS may contain unpatched vulnerabilities",
                    "adb_command": None,
                    "source": "security_best_practices",
                })
        except (ValueError, IndexError):
            pass

    build_type = device_info.get("build_type", "")
    if build_type == "eng":
        result.add({
            "type": TYPE_REVIEW,
            "priority": PRIORITY_HIGH,
            "target": "build_type",
            "target_name": "Engineering Build",
            "reason": "Device is running engineering build — not suitable for production",
            "risk": "Engineering builds have reduced security controls",
            "adb_command": None,
            "source": "security_best_practices",
        })

    debuggable = device_info.get("debuggable", "")
    if debuggable == "1":
        result.add({
            "type": TYPE_REVIEW,
            "priority": PRIORITY_HIGH,
            "target": "debuggable",
            "target_name": "Debug Mode Enabled",
            "reason": "Device is debuggable — potential security risk",
            "risk": "Debuggable devices can be compromised more easily",
            "adb_command": None,
            "source": "security_best_practices",
        })


# ============================================================
# HELPERS
# ============================================================

def _report(on_progress, pct: int, msg: str):
    if on_progress:
        try:
            on_progress(pct, msg)
        except Exception:
            pass
