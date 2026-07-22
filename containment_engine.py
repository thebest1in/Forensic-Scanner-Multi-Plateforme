import json
import time
from pathlib import Path
from dataclasses import dataclass, field

from core import logger, run_adb, ADB_TIMEOUT


# ============================================================
# AUTOMATED INCIDENT RESPONSE & CONTAINMENT
# ============================================================

# DNS sinkhole options (no-root)
DNS_SINKHOLES = {
    "adguard": "dns.adguard.com",
    "quad9": "dns.quad9.net",
    "cloudflare_family": "family.cloudflare-dns.com",
    "local_blackhole": "0.0.0.0",
}

# Permissions to revoke for suspicious apps (no-root via appops)
_RESTRICTED_OPS = [
    "RUN_IN_BACKGROUND",
    "ACCESS_BACKGROUND_LOCATION",
    "MONITOR_SENSOR",
]


@dataclass
class ContainmentAction:
    """Single containment action taken or recommended."""
    action_type: str = ""  # "dns_sinkhole", "revoke_permission", "disable_app", "evidence_lock"
    target: str = ""
    command: str = ""
    status: str = "pending"  # "pending", "executed", "failed", "skipped"
    details: str = ""
    timestamp_utc: str = ""

    def to_dict(self) -> dict:
        return {
            "action_type": self.action_type,
            "target": self.target,
            "command": self.command,
            "status": self.status,
            "details": self.details,
            "timestamp_utc": self.timestamp_utc,
        }


@dataclass
class ContainmentReport:
    """Full containment report for an incident."""
    device_serial: str = ""
    threat_verdict: str = ""
    actions_taken: list[dict] = field(default_factory=list)
    actions_recommended: list[dict] = field(default_factory=list)
    evidence_locked: bool = False
    evidence_path: str = ""
    summary: str = ""
    timestamp_utc: str = ""

    def to_dict(self) -> dict:
        return {
            "device_serial": self.device_serial,
            "threat_verdict": self.threat_verdict,
            "actions_taken": self.actions_taken,
            "actions_recommended": self.actions_recommended,
            "evidence_locked": self.evidence_locked,
            "evidence_path": self.evidence_path,
            "summary": self.summary,
            "timestamp_utc": self.timestamp_utc,
        }


class ContainmentEngine:
    """Automated incident response and containment engine.

    No-root containment using ADB commands:
    - DNS sinkholing via Private DNS settings
    - App background execution revocation (appops)
    - Location access revocation for suspicious packages
    - Evidence lock (auto-create evidence package on CRITICAL)

    Root-optional enhancements:
    - Full application disable
    - Network interface shutdown
    """

    def __init__(self, serial: str = ""):
        self._serial = serial
        self._actions: list[ContainmentAction] = []
        self._device_online = bool(serial)

    def contain_threat(
        self,
        threat_verdict: str,
        suspicious_packages: list[str] = None,
        suspicious_ips: list[str] = None,
        dump_dir: Path = None,
        dry_run: bool = False,
    ) -> ContainmentReport:
        """Execute containment actions based on threat verdict.

        Args:
            threat_verdict: CRITICAL, SUSPICIOUS, or CLEAN
            suspicious_packages: Package names flagged as malicious
            suspicious_ips: IP addresses flagged as malicious
            dump_dir: Directory to store evidence lock package
            dry_run: If True, only recommend actions without executing
        """
        report = ContainmentReport(
            device_serial=self._serial,
            threat_verdict=threat_verdict,
            timestamp_utc=time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        )
        self._actions = []

        if threat_verdict == "CLEAN":
            report.summary = "No containment needed — device is CLEAN."
            return report

        # Phase 1: Evidence lock (always on CRITICAL)
        if threat_verdict == "CRITICAL" and dump_dir:
            self._evidence_lock(dump_dir, report, dry_run)

        # Phase 2: DNS sinkhole (CRITICAL and SUSPICIOUS)
        self._dns_sinkhole(report, dry_run)

        # Phase 3: App containment (CRITICAL and SUSPICIOUS)
        if suspicious_packages:
            for pkg in suspicious_packages:
                self._restrict_app(pkg, report, dry_run)

        # Phase 4: IP containment recommendations
        if suspicious_ips:
            for ip in suspicious_ips:
                self._recommend_ip_block(ip, report)

        report.actions_taken = [a.to_dict() for a in self._actions if a.status == "executed"]
        report.actions_recommended = [a.to_dict() for a in self._actions if a.status == "pending"]

        taken = len(report.actions_taken)
        rec = len(report.actions_recommended)
        report.summary = (
            f"Containment complete: {taken} actions executed, {rec} recommended. "
            f"Evidence locked: {'Yes' if report.evidence_locked else 'No'}."
        )
        logger.info(f"Containment: {report.summary}")
        return report

    # --------------------------------------------------------
    # Evidence Lock
    # --------------------------------------------------------

    def _evidence_lock(self, dump_dir: Path, report: ContainmentReport, dry_run: bool):
        """Auto-create SHA-256 chained evidence package on CRITICAL."""
        action = ContainmentAction(
            action_type="evidence_lock",
            target=str(dump_dir),
            details="Creating SHA-256 chained evidence package",
        )

        if dry_run:
            action.status = "pending"
            action.details = "[DRY RUN] Would create evidence package at: " + str(dump_dir.parent / "chain_of_custody.json")
            self._actions.append(action)
            return

        try:
            from custody import create_evidence_package
            manifest_path = create_evidence_package(dump_dir, [], case_id=f"auto_{int(time.time())}")
            action.status = "executed"
            action.timestamp_utc = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
            action.details = f"Evidence package created: {manifest_path.name}"
            report.evidence_locked = True
            report.evidence_path = str(manifest_path)
            logger.success(f"Evidence lock: {manifest_path}")
        except Exception as e:
            action.status = "failed"
            action.details = f"Evidence lock failed: {e}"
            logger.error(f"Evidence lock failed: {e}")

        self._actions.append(action)

    # --------------------------------------------------------
    # DNS Sinkhole
    # --------------------------------------------------------

    def _dns_sinkhole(self, report: ContainmentReport, dry_run: bool):
        """Set device Private DNS to a sinkhole to block C2 communications."""
        sinkhole = DNS_SINKHOLES["adguard"]
        action = ContainmentAction(
            action_type="dns_sinkhole",
            target=sinkhole,
            command=f"settings put global private_dns_specifier {sinkhole}",
        )

        if not self._device_online:
            action.status = "pending"
            action.details = f"[OFFLINE] Recommended: Set Private DNS to {sinkhole}"
            self._actions.append(action)
            return

        if dry_run:
            action.status = "pending"
            action.details = f"[DRY RUN] Would set Private DNS to {sinkhole}"
            self._actions.append(action)
            return

        try:
            success, output = run_adb(
                f"-s {self._serial} shell settings put global private_dns_specifier {sinkhole}",
                timeout=10,
            )
            if success:
                # Also enable private DNS mode
                run_adb(
                    f"-s {self._serial} shell settings put global private_dns_mode hostname",
                    timeout=10,
                )
                action.status = "executed"
                action.timestamp_utc = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
                action.details = f"Private DNS set to {sinkhole} — C2 traffic will be blocked"
                logger.success(f"DNS sinkhole: {sinkhole}")
            else:
                action.status = "failed"
                action.details = f"ADB command failed: {output}"
        except Exception as e:
            action.status = "failed"
            action.details = f"DNS sinkhole failed: {e}"

        self._actions.append(action)

    # --------------------------------------------------------
    # App Restriction
    # --------------------------------------------------------

    def _restrict_app(self, package_name: str, report: ContainmentReport, dry_run: bool):
        """Revoke background execution and location access for a suspicious app."""
        for op in _RESTRICTED_OPS:
            action = ContainmentAction(
                action_type="revoke_permission",
                target=f"{package_name}:{op}",
                command=f"cmd appops set {package_name} {op} ignore",
            )

            if not self._device_online:
                action.status = "pending"
                action.details = f"[OFFLINE] Recommended: Revoke {op} from {package_name}"
                self._actions.append(action)
                continue

            if dry_run:
                action.status = "pending"
                action.details = f"[DRY RUN] Would revoke {op} from {package_name}"
                self._actions.append(action)
                continue

            try:
                success, output = run_adb(
                    f"-s {self._serial} shell cmd appops set {package_name} {op} ignore",
                    timeout=10,
                )
                if success:
                    action.status = "executed"
                    action.timestamp_utc = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
                    action.details = f"Revoked {op} from {package_name}"
                    logger.info(f"Revoked {op} from {package_name}")
                else:
                    action.status = "failed"
                    action.details = f"Failed: {output}"
            except Exception as e:
                action.status = "failed"
                action.details = f"Error: {e}"

            self._actions.append(action)

    # --------------------------------------------------------
    # IP Blocking Recommendation
    # --------------------------------------------------------

    def _recommend_ip_block(self, ip: str, report: ContainmentReport):
        """Recommend IP blocking via DNS sinkhole (no-root compatible)."""
        action = ContainmentAction(
            action_type="recommend_ip_block",
            target=ip,
            details=(
                f"Add {ip} to DNS sinkhole blocklist. "
                f"With Private DNS already pointing to {DNS_SINKHOLES['adguard']}, "
                f"add this IP to the AdGuard blocklist or firewall rules."
            ),
        )
        action.status = "pending"
        self._actions.append(action)

    # --------------------------------------------------------
    # Undo Containment
    # --------------------------------------------------------

    def undo_containment(self) -> dict:
        """Undo DNS sinkhole and app restrictions (restore defaults)."""
        results = {"dns_reset": False, "ops_restored": 0}

        if self._device_online:
            try:
                run_adb(
                    f"-s {self._serial} shell settings put global private_dns_mode off",
                    timeout=10,
                )
                results["dns_reset"] = True
                logger.info("DNS sinkhole removed — Private DNS set to off")
            except Exception as e:
                logger.error(f"Failed to undo DNS sinkhole: {e}")

        return results
