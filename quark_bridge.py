import json
from pathlib import Path
from dataclasses import dataclass, field

from core import logger


# ============================================================
# QUARK ENGINE BEHAVIORAL ANALYSIS
# ============================================================

# Threat behavior categories that Quark detects
_THREAT_CATEGORIES = {
    "intercept_sms": {"severity": "critical", "description": "Intercepts SMS messages"},
    "send_sms": {"severity": "critical", "description": "Sends SMS to premium numbers"},
    "record_audio": {"severity": "critical", "description": "Records ambient audio"},
    "capture_screen": {"severity": "critical", "description": "Captures screen contents"},
    "capture_video": {"severity": "critical", "description": "Captures video via camera"},
    "get_location": {"severity": "high", "description": "Accesses GPS location"},
    "track_location": {"severity": "high", "description": "Tracks location in background"},
    "access_contacts": {"severity": "high", "description": "Reads contact list"},
    "access_call_log": {"severity": "high", "description": "Reads call history"},
    "access_calendar": {"severity": "medium", "description": "Reads calendar events"},
    "get_installed_apps": {"severity": "medium", "description": "Enumerates installed packages"},
    "get_account_info": {"severity": "high", "description": "Reads account credentials"},
    "access_clipboard": {"severity": "high", "description": "Reads clipboard contents"},
    "vibrate": {"severity": "low", "description": "Triggers device vibration"},
    "get_imei": {"severity": "high", "description": "Reads device IMEI"},
    "access_notification": {"severity": "high", "description": "Reads notification contents"},
    "take_photo": {"severity": "critical", "description": "Takes photo silently"},
    "make_call": {"severity": "high", "description": "Initiates phone call"},
    "open_url": {"severity": "medium", "description": "Opens URL in browser"},
    "execute_command": {"severity": "critical", "description": "Executes shell command"},
    "download_file": {"severity": "high", "description": "Downloads file from remote"},
    "connect_internet": {"severity": "medium", "description": "Establishes network connection"},
    "crypto_miner": {"severity": "critical", "description": "Cryptocurrency mining detected"},
    "keylogger": {"severity": "critical", "description": "Keylogger behavior detected"},
    "hide_icon": {"severity": "high", "description": "Hides launcher icon"},
    "overlay_attack": {"severity": "critical", "description": "UI overlay attack"},
    "prevent_uninstall": {"severity": "critical", "description": "Prevents app uninstallation"},
}


@dataclass
class QuarkResult:
    """Result of Quark-Engine behavioral analysis on a single APK."""
    package_name: str = ""
    apk_path: str = ""
    threat_score: float = 0.0  # 0.0 - 1.0
    threat_level: str = "CLEAN"
    matched_rules: list[dict] = field(default_factory=list)
    malicious_behaviors: list[str] = field(default_factory=list)
    privacy_violations: list[str] = field(default_factory=list)
    capability_count: int = 0
    rule_match_count: int = 0
    details: str = ""

    def to_dict(self) -> dict:
        return {
            "package_name": self.package_name,
            "apk_path": self.apk_path,
            "threat_score": round(self.threat_score, 4),
            "threat_level": self.threat_level,
            "matched_rules": self.matched_rules,
            "malicious_behaviors": self.malicious_behaviors,
            "privacy_violations": self.privacy_violations,
            "capability_count": self.capability_count,
            "rule_match_count": self.rule_match_count,
            "details": self.details,
        }


class QuarkBridge:
    """Behavioral malware analysis using Quark-Engine.

    Quark-Engine analyzes Dalvik bytecode to detect malicious behaviors
    by matching app code against hundreds of threat behavior rules.
    It provides a threat score based on behavioral patterns like:
    - SMS interception and premium SMS sending
    - Audio/video recording without consent
    - Location tracking and contact exfiltration
    - Hidden icon and anti-uninstall techniques
    """

    @staticmethod
    def check_quark_available() -> bool:
        """Check if quark-engine is installed."""
        try:
            from quark.core import Quark
            return True
        except ImportError:
            return False

    def scan_apk(self, apk_path: Path) -> QuarkResult:
        """Run Quark-Engine behavioral analysis on a single APK."""
        result = QuarkResult(apk_path=str(apk_path))

        if not apk_path.exists():
            logger.warning(f"APK not found for Quark: {apk_path}")
            return result

        result.package_name = apk_path.stem

        try:
            from quark.core import Quark
            from quark.rule import Rule

            quark = Quark(str(apk_path))
            rule_path = Path(__file__).parent / "rules" / "quark_rules"
            rule_files = list(rule_path.glob("*.json")) if rule_path.exists() else []

            if not rule_files:
                logger.info("No Quark rules found — using built-in analysis")
                return self._fallback_analysis(apk_path, result)

            for rf in rule_files:
                try:
                    rule = Rule(str(rf))
                    match = quark.run(rule)
                    if match and getattr(match, "confidence", 0) > 50:
                        rule_data = {
                            "rule": rf.stem,
                            "confidence": getattr(match, "confidence", 0),
                            "description": rule.description if hasattr(rule, "description") else "",
                        }
                        result.matched_rules.append(rule_data)
                        result.rule_match_count += 1

                        desc = rule_data["description"].lower()
                        for cat, info in _THREAT_CATEGORIES.items():
                            if cat.replace("_", " ") in desc or cat.replace("_", "") in desc:
                                result.malicious_behaviors.append(info["description"])
                except Exception as e:
                    logger.debug(f"Quark rule {rf.name} failed: {e}")

            result.capability_count = len(result.malicious_behaviors)
            result.threat_score = self._compute_score(result)
            result.threat_level = self._score_to_threat(result.threat_score)

        except ImportError:
            logger.info("quark-engine not installed — using fallback analysis")
            return self._fallback_analysis(apk_path, result)
        except Exception as e:
            logger.error(f"Quark scan failed for {apk_path.name}: {e}")

        if result.threat_score > 0:
            logger.warning(
                f"Quark: {result.package_name} -> score={result.threat_score:.2f} "
                f"({result.threat_level}) behaviors={result.capability_count}"
            )
        return result

    def scan_directory(self, directory: Path) -> list[QuarkResult]:
        """Scan all APKs in a directory."""
        results = []
        apk_files = list(directory.rglob("*.apk"))
        if not apk_files:
            return results

        logger.info(f"Quark: scanning {len(apk_files)} APKs")
        for apk in apk_files:
            results.append(self.scan_apk(apk))
        return results

    def _fallback_analysis(self, apk_path: Path, result: QuarkResult) -> QuarkResult:
        """Fallback behavioral analysis using static heuristic checks when Quark unavailable."""
        try:
            import zipfile
            if not zipfile.is_zipfile(str(apk_path)):
                return result

            with zipfile.ZipFile(str(apk_path), "r") as zf:
                names = zf.namelist()
                dex_files = [n for n in names if n.endswith(".dex")]
                result.capability_count = len(dex_files)

                android_manifest = None
                for name in names:
                    if name == "AndroidManifest.xml":
                        try:
                            android_manifest = zf.read(name)
                        except Exception:
                            pass
                        break

                if android_manifest:
                    content = android_manifest.decode("utf-8", errors="replace")

                    suspicious_strings = [
                        "intercept", "sms", "audio", "record", "camera",
                        "location", "gps", "contact", "clipboard", "keylog",
                        "screenshot", "screen_record", "vibrate",
                    ]
                    for s in suspicious_strings:
                        if s.lower() in content.lower():
                            result.malicious_behaviors.append(f"Static: {s} reference in manifest")

                result.capability_count = max(len(dex_files), len(result.malicious_behaviors))
                result.threat_score = self._compute_score(result)
                result.threat_level = self._score_to_threat(result.threat_score)
                result.details = "Fallback analysis (quark-engine unavailable)"
        except Exception as e:
            logger.debug(f"Quark fallback failed for {apk_path.name}: {e}")
        return result

    def _compute_score(self, result: QuarkResult) -> float:
        """Compute 0.0-1.0 threat score from behavioral findings."""
        if not result.matched_rules and not result.malicious_behaviors:
            return 0.0

        rule_score = min(result.rule_match_count * 0.15, 0.6)
        behavior_score = min(len(result.malicious_behaviors) * 0.12, 0.4)
        return min(rule_score + behavior_score, 1.0)

    @staticmethod
    def _score_to_threat(score: float) -> str:
        if score >= 0.7:
            return "CRITICAL"
        if score >= 0.4:
            return "SUSPICIOUS"
        return "CLEAN"
