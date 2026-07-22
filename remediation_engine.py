import re
from pathlib import Path

from core import logger


# ============================================================
# REMEDIATION ACTIONS
# ============================================================

ACTION_DELETE = "DELETE"
ACTION_UPDATE = "UPDATE"
ACTION_RESTRICT = "RESTRICT"
ACTION_NONE = "NONE"

ACTION_LABELS = {
    ACTION_DELETE: "DELETE (Uninstall Immediately)",
    ACTION_UPDATE: "UPDATE (Patch / Upgrade)",
    ACTION_RESTRICT: "RESTRICT (Revoke Permissions)",
    ACTION_NONE: "No Action Required",
}

ACTION_COLORS = {
    ACTION_DELETE: "#e74c3c",
    ACTION_UPDATE: "#f39c12",
    ACTION_RESTRICT: "#3498db",
    ACTION_NONE: "#2ecc71",
}

ACTION_ICONS = {
    ACTION_DELETE: "DELETE",
    ACTION_UPDATE: "UPDATE",
    ACTION_RESTRICT: "RESTRICT",
    ACTION_NONE: "OK",
}


# ============================================================
# KNOWN MALWARE / SPYWARE DATABASES
# ============================================================

KNOWN_MALWARE_PACKAGES = {
    "com.flexispy", "com.mspy.lite", "com.mspy.pro", "com.cerberus",
    "com.spybubble", "com.mobilespy", "com.android.sys.update.co",
    "com.android.service.update", "com.google.service.helper",
    "com.xiaomi.system.update.service", "com.droidjack",
    "net.droidjack.server", "com.sandrorat", "com.hackingteam",
    "com.finspy", "com.novispy", "com.dendroid",
    "com.highstermobile", "com.traccar.client",
    "com.prey", "com.life360.android",
}

CRITICAL_YARA_TAGS = {
    "pegasus", "zero_click", "novispy", "finspy", "dendroid",
    "hackingteam", "sandrorat", "reverse_shell",
}

SUSPICIOUS_YARA_TAGS = {
    "disguised_package", "stalkerware", "credential_theft",
    "data_exfil", "spyware", "battery_drain",
}

# System apps that should NEVER be deleted
SYSTEM_APP_PREFIXES = (
    "com.android.", "com.google.", "com.qualcomm.", "com.mediatek.",
    "com.xiaomi.", "com.miui.", "com.milink.", "com.qti.",
    "com.wapi.", "org.codeaurora.", "android.",
)

# System apps that CAN be updated via Play Store
UPDATABLE_SYSTEM_APPS = {
    "com.android.chrome", "com.google.android.gm",
    "com.google.android.apps.maps", "com.google.android.youtube",
    "com.google.android.calendar", "com.google.android.contacts",
}


# ============================================================
# REMEDIATION RESULT
# ============================================================

class RemediationResult:
    def __init__(self):
        self.actions: list[dict] = []

    def to_dict(self) -> dict:
        return {
            "total_actions": len(self.actions),
            "delete_count": sum(1 for a in self.actions if a["action"] == ACTION_DELETE),
            "update_count": sum(1 for a in self.actions if a["action"] == ACTION_UPDATE),
            "restrict_count": sum(1 for a in self.actions if a["action"] == ACTION_RESTRICT),
            "actions": self.actions,
        }


# ============================================================
# MAIN REMEDIATION ENGINE
# ============================================================

def analyze_remediation(
    analysis_result,
    extracted_files: dict[str, Path] | None = None,
    third_party_packages: list[str] | None = None,
    on_progress=None,
) -> RemediationResult:
    """
    Evaluate all findings from analyzer + heuristics and generate
    concrete remediation actions: DELETE, UPDATE, or RESTRICT.
    """
    result = RemediationResult()

    _report(on_progress, 10, "Evaluating YARA matches for remediation...")
    _process_yara_matches(analysis_result, result)

    _report(on_progress, 40, "Evaluating heuristic findings...")
    _process_heuristic_findings(analysis_result, result)

    _report(on_progress, 60, "Evaluating suspicious IPs...")
    _process_suspicious_ips(analysis_result, result)

    _report(on_progress, 75, "Evaluating over-privileged packages...")
    _process_overprivileged(analysis_result, result)

    _report(on_progress, 90, "Deduplicating actions...")
    result.actions = _deduplicate_actions(result.actions)

    _report(on_progress, 100, f"Remediation complete: {len(result.actions)} actions recommended.")
    return result


# ============================================================
# PROCESSOR: YARA MATCHES
# ============================================================

def _process_yara_matches(analysis_result, result: RemediationResult):
    """Evaluate each YARA match and assign DELETE or RESTRICT."""
    for match in analysis_result.matched_rules:
        if not match.get("authoritative", True):
            continue
        rule_name = match.get("rule", "")
        tags = {t.lower() for t in match.get("tags", [])}
        source_file = match.get("file", "")
        severity = match.get("meta", {}).get("severity", "MEDIUM")

        # CRITICAL rules → DELETE
        if tags & CRITICAL_YARA_TAGS or any(ct in rule_name.lower() for ct in CRITICAL_YARA_TAGS):
            pkg = _extract_package_from_context(match)
            result.actions.append({
                "action": ACTION_DELETE,
                "target": pkg or rule_name,
                "target_type": "package" if pkg else "rule",
                "reason": f"Critical malware signature: {rule_name}",
                "severity": "CRITICAL",
                "evidence": f"YARA rule '{rule_name}' matched in {source_file}",
                "adb_command": f"adb uninstall {pkg}" if pkg else None,
                "source": source_file,
            })
            logger.warning(f"Remediation DELETE: {pkg or rule_name} (YARA: {rule_name})")

        # SUSPICIOUS rules → RESTRICT or UPDATE depending on context
        elif tags & SUSPICIOUS_YARA_TAGS or any(su in rule_name.lower() for su in SUSPICIOUS_YARA_TAGS):
            pkg = _extract_package_from_context(match)
            if pkg and _is_system_app(pkg):
                result.actions.append({
                    "action": ACTION_UPDATE,
                    "target": pkg,
                    "target_type": "system_package",
                    "reason": f"Suspicious system component: {rule_name}",
                    "severity": "HIGH",
                    "evidence": f"YARA rule '{rule_name}' matched in {source_file}",
                    "adb_command": None,
                    "source": source_file,
                })
            elif pkg:
                result.actions.append({
                    "action": ACTION_RESTRICT,
                    "target": pkg,
                    "target_type": "package",
                    "reason": f"Suspicious behavior detected: {rule_name}",
                    "severity": "MEDIUM",
                    "evidence": f"YARA rule '{rule_name}' matched in {source_file}",
                    "adb_command": _build_revoke_permissions_cmd(pkg, rule_name),
                    "source": source_file,
                })
            else:
                result.actions.append({
                    "action": ACTION_RESTRICT,
                    "target": rule_name,
                    "target_type": "artifact",
                    "reason": f"Suspicious pattern in artifact: {rule_name}",
                    "severity": "MEDIUM",
                    "evidence": f"YARA rule '{rule_name}' in {source_file}",
                    "adb_command": None,
                    "source": source_file,
                })


# ============================================================
# PROCESSOR: HEURISTIC FINDINGS
# ============================================================

def _process_heuristic_findings(analysis_result, result: RemediationResult):
    """Evaluate heuristic flagged packages."""
    if not analysis_result.heuristic_result:
        return

    hr = analysis_result.heuristic_result
    risk_score = hr.get("risk_score", 0)

    for pkg_info in hr.get("flagged_packages", []):
        pkg = pkg_info.get("package", "")
        pkg_score = pkg_info.get("score", 0)
        reasons = pkg_info.get("reasons", [])
        pkg_risk = pkg_info.get("risk", "LOW")

        if pkg == "unknown_accessibility":
            continue

        # High score (80+) → DELETE
        if pkg_score >= 40:
            action = ACTION_DELETE
            severity = "CRITICAL"
        # Medium score → RESTRICT
        elif pkg_score >= 10:
            action = ACTION_RESTRICT
            severity = "HIGH"
        else:
            action = ACTION_RESTRICT
            severity = "MEDIUM"

        # System apps: never DELETE, only UPDATE or RESTRICT
        if _is_system_app(pkg) and action == ACTION_DELETE:
            if pkg in UPDATABLE_SYSTEM_APPS:
                action = ACTION_UPDATE
            else:
                action = ACTION_RESTRICT
                severity = "HIGH"

        adb_cmd = None
        if action == ACTION_DELETE:
            adb_cmd = f"adb uninstall {pkg}"
        elif action == ACTION_RESTRICT:
            adb_cmd = _build_revoke_permissions_cmd(pkg, reasons[0] if reasons else "overprivileged")

        result.actions.append({
            "action": action,
            "target": pkg,
            "target_type": "system_package" if _is_system_app(pkg) else "package",
            "reason": "; ".join(reasons),
            "severity": severity,
            "evidence": f"Heuristic score: {pkg_score}/100, risk: {pkg_risk}",
            "adb_command": adb_cmd,
            "source": "heuristics",
        })
        logger.info(f"Remediation {action}: {pkg} (score={pkg_score})")


# ============================================================
# PROCESSOR: SUSPICIOUS IPs
# ============================================================

def _process_suspicious_ips(analysis_result, result: RemediationResult):
    """Flag suspicious IP communications for network restriction."""
    for ip in analysis_result.suspicious_ips:
        ip_str = ip if isinstance(ip, str) else ip.get("ip", str(ip))
        result.actions.append({
            "action": ACTION_RESTRICT,
            "target": ip_str,
            "target_type": "ip_address",
            "reason": f"Known malicious IP in network traffic",
            "severity": "HIGH",
            "evidence": f"IP {ip_str} found in extracted artifacts",
            "adb_command": f"adb shell iptables -A OUTPUT -d {ip_str} -j DROP",
            "source": "ioc_crossref",
        })


# ============================================================
# PROCESSOR: OVER-PRIVILEGED APPS
# ============================================================

def _process_overprivileged(analysis_result, result: RemediationResult):
    """Check for clean apps with excessive permissions."""
    if not analysis_result.heuristic_result:
        return

    hr = analysis_result.heuristic_result
    for combo in hr.get("suspicious_combos", []):
        combo_permissions = combo.get("permissions", [])
        combo_apps = combo.get("packages", [])

        for pkg in combo_apps:
            if _is_system_app(pkg):
                continue
            # Already handled by heuristic flagged_packages?
            already_handled = any(
                a["target"] == pkg for a in result.actions
            )
            if already_handled:
                continue

            result.actions.append({
                "action": ACTION_RESTRICT,
                "target": pkg,
                "target_type": "package",
                "reason": f"Suspicious permission combination: {', '.join(combo_permissions[:3])}",
                "severity": "MEDIUM",
                "evidence": f"Permission combo detected",
                "adb_command": _build_revoke_permissions_cmd(pkg, "combo"),
                "source": "heuristics",
            })


# ============================================================
# HELPERS
# ============================================================

def _extract_package_from_context(match: dict) -> str | None:
    """Try to extract a package name from YARA match context."""
    rule_name = match.get("rule", "").lower()
    source = match.get("file", "").lower()

    known = {
        "pegasus": None, "novispy": "com.novispy",
        "finspy": "com.finspy", "dendroid": "com.dendroid",
        "hackingteam": "com.hackingteam", "sandrorat": "com.sandrorat",
    }
    for key, pkg in known.items():
        if key in rule_name:
            return pkg

    # Try to find package name pattern in rule name
    pkg_match = re.search(r"com\.[a-z.]+", rule_name)
    if pkg_match:
        return pkg_match.group(0)

    return None


def _is_system_app(package_name: str) -> bool:
    """Check if a package is a system application."""
    return any(package_name.startswith(p) for p in SYSTEM_APP_PREFIXES)


def _build_revoke_permissions_cmd(pkg: str, reason: str) -> str:
    """Build an ADB command to revoke a dangerous permission."""
    # Revoke the most dangerous permission based on reason reason
    reason_lower = reason.lower()
    if "sms" in reason_lower:
        return f"adb shell pm revoke {pkg} android.permission.READ_SMS"
    if "audio" in reason_lower or "record" in reason_lower:
        return f"adb shell pm revoke {pkg} android.permission.RECORD_AUDIO"
    if "camera" in reason_lower:
        return f"adb shell pm revoke {pkg} android.permission.CAMERA"
    if "location" in reason_lower:
        return f"adb shell pm revoke {pkg} android.permission.ACCESS_FINE_LOCATION"
    if "contact" in reason_lower:
        return f"adb shell pm revoke {pkg} android.permission.READ_CONTACTS"
    if "overlay" in reason_lower or "alert" in reason_lower:
        return f"adb shell pm revoke {pkg} android.permission.SYSTEM_ALERT_WINDOW"
    if "admin" in reason_lower:
        return f"adb shell dpm remove-active-admin {pkg}/.DeviceAdminReceiver"
    if "accessibility" in reason_lower:
        return f"adb shell settings put secure enabled_accessibility_services ''"
    # Generic: revoke READ_SMS as a safe default
    return f"adb shell pm revoke {pkg} android.permission.READ_SMS"


def _deduplicate_actions(actions: list[dict]) -> list[dict]:
    """Remove duplicate actions, keeping the highest severity for each target."""
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    action_order = {ACTION_DELETE: 0, ACTION_UPDATE: 1, ACTION_RESTRICT: 2, ACTION_NONE: 3}

    best: dict[str, dict] = {}
    for a in actions:
        key = f"{a['target']}:{a['action']}"
        if key not in best:
            best[key] = a
        else:
            existing = best[key]
            e_sev = severity_order.get(existing["severity"], 9)
            n_sev = severity_order.get(a["severity"], 9)
            e_act = action_order.get(existing["action"], 9)
            n_act = action_order.get(a["action"], 9)
            if n_sev < e_sev or (n_sev == e_sev and n_act < e_act):
                best[key] = a

    return sorted(
        best.values(),
        key=lambda x: (severity_order.get(x["severity"], 9), action_order.get(x["action"], 9)),
    )


def _report(on_progress, percent, message):
    if on_progress:
        try:
            on_progress(percent, message)
        except Exception:
            pass
