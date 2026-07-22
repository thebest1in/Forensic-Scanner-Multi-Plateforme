import os
import time
from dataclasses import dataclass, field
from pathlib import Path

import requests

from core import logger

# ============================================================
# MOBSF BRIDGE - Mobile Security Framework REST API Integration
# ============================================================

MOBSF_DEFAULT_URL = "http://localhost:8000"
MOBSF_UPLOAD_TIMEOUT = 60
MOBSF_SCAN_TIMEOUT = 300
MOBSF_REPORT_TIMEOUT = 60

# Dangerous permission categories from MobSF
DANGEROUS_PERMISSION_GROUPS = {
    "android.permission.READ_SMS": "messaging",
    "android.permission.RECEIVE_SMS": "messaging",
    "android.permission.SEND_SMS": "messaging",
    "android.permission.READ_CONTACTS": "contacts",
    "android.permission.READ_CALL_LOG": "phone",
    "android.permission.READ_PHONE_STATE": "phone",
    "android.permission.CAMERA": "camera",
    "android.permission.RECORD_AUDIO": "microphone",
    "android.permission.ACCESS_FINE_LOCATION": "location",
    "android.permission.ACCESS_COARSE_LOCATION": "location",
    "android.permission.WRITE_SETTINGS": "system",
    "android.permission.BIND_ACCESSIBILITY_SERVICE": "accessibility",
    "android.permission.BIND_DEVICE_ADMIN": "device_admin",
    "android.permission.READ_EXTERNAL_STORAGE": "storage",
    "android.permission.WRITE_EXTERNAL_STORAGE": "storage",
    "android.permission.INTERNET": "network",
    "android.permission.INSTALL_PACKAGES": "packages",
    "android.permission.DELETE_PACKAGES": "packages",
    "android.permission.ACCESS_BACKGROUND_LOCATION": "location",
    "android.permission.PROCESS_OUTGOING_CALLS": "phone",
    "android.permission.READ_MEDIA_IMAGES": "media",
    "android.permission.READ_MEDIA_VIDEO": "media",
    "android.permission.READ_MEDIA_AUDIO": "media",
    "android.permission.POST_NOTIFICATIONS": "notifications",
    "android.permission.NEARBY_WIFI_DEVICES": "wifi",
    "android.permission.BLUETOID_SCAN": "bluetooth",
    "android.permission.BLUETOID_CONNECT": "bluetooth",
}

# High-risk activities that indicate surveillance or malicious behavior
SUSPICIOUS_ACTIVITIES = {
    "DeviceAdmin": "device_admin",
    "AccessibilityService": "accessibility",
    "VPNService": "vpn",
    "Overlay": "overlay",
    "Keyguard": "lock_screen",
    "WallpaperService": "wallpaper",
    "InputMethod": "keyboard",
}

# Known spyware package names
KNOWN_SPYWARE_PACKAGES = {
    "com.flexispy", "com.mspy", "com.highster", "com.thetruthspy",
    "com.sandrorat", "net.droidjack", "com.springsolutions",
    "com.widdit", "com.luxferre", "com.surqs", "com.fouadware",
    "com.hawk.android", "com.venum", "com.phonesheriff",
    "com.retina.je", "com.pretulian.spyphone", "com.childparental",
    "com.bkphone", "com.willdev", "com.anydesk.anydeskandroid",
    "com.ear.spy", "com.turbo.vpn", "com.v720",
    "com.nst.spyphone", "com.ground.android",
}


@dataclass
class MobSFResult:
    """Results from MobSF static analysis."""
    available: bool = False
    apk_name: str = ""
    package_name: str = ""
    version_name: str = ""
    version_code: int = 0
    target_sdk: int = 0
    min_sdk: int = 0

    permissions: list[dict] = field(default_factory=list)
    dangerous_permissions: list[dict] = field(default_factory=list)
    activities: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    receivers: list[str] = field(default_factory=list)
    providers: list[str] = field(default_factory=list)

    certificate_info: dict = field(default_factory=dict)
    certificate_verified: bool = False

    code_analysis: list[dict] = field(default_factory=list)
    secrets: list[dict] = field(default_factory=list)

    urls: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)

    manifest_analysis: list[dict] = field(default_factory=list)
    manifest_malware_perms: list[str] = field(default_factory=list)

    appsec_score: float = 0.0
    highest_risk: str = "info"
    spyware_detected: list[str] = field(default_factory=list)

    details: str = ""

    @property
    def has_findings(self) -> bool:
        return bool(
            self.dangerous_permissions
            or self.secrets
            or self.spyware_detected
            or self.manifest_malware_perms
        )

    @property
    def severity(self) -> str:
        if not self.available:
            return "UNAVAILABLE"
        if self.spyware_detected:
            return "CRITICAL"
        if self.secrets or self.manifest_malware_perms:
            return "SUSPICIOUS"
        if len(self.dangerous_permissions) > 10:
            return "SUSPICIOUS"
        return "CLEAN"

    def to_dict(self) -> dict:
        return {
            "available": self.available,
            "apk_name": self.apk_name,
            "package_name": self.package_name,
            "version_name": self.version_name,
            "version_code": self.version_code,
            "target_sdk": self.target_sdk,
            "min_sdk": self.min_sdk,
            "permissions_total": len(self.permissions),
            "dangerous_permissions": self.dangerous_permissions,
            "activities_count": len(self.activities),
            "services_count": len(self.services),
            "receivers_count": len(self.receivers),
            "providers_count": len(self.providers),
            "certificate_info": self.certificate_info,
            "certificate_verified": self.certificate_verified,
            "code_analysis": self.code_analysis[:50],
            "secrets": self.secrets,
            "urls": self.urls[:100],
            "domains": self.domains[:100],
            "ips": self.ips[:100],
            "manifest_analysis": self.manifest_analysis[:50],
            "manifest_malware_perms": self.manifest_malware_perms,
            "appsec_score": self.appsec_score,
            "highest_risk": self.highest_risk,
            "spyware_detected": self.spyware_detected,
            "severity": self.severity,
            "details": self.details,
        }


def _get_mobsf_config() -> tuple[str, str | None]:
    """Get MobSF URL and API key from environment or defaults."""
    url = os.environ.get("MOBSF_URL", MOBSF_DEFAULT_URL)
    api_key = os.environ.get("MOBSF_API_KEY")
    if not api_key:
        key_file = Path.home() / ".mobsf" / "api_key"
        if key_file.exists():
            api_key = key_file.read_text(encoding="utf-8").strip()
    return url, api_key


def check_mobsf_available(url: str = None, api_key: str = None) -> bool:
    """Check if MobSF is running and accessible."""
    if url is None:
        url, api_key_from_config = _get_mobsf_config()
        if api_key is None:
            api_key = api_key_from_config
    try:
        resp = requests.get(
            f"{url}/api/v1/",
            headers={"Authorization": api_key} if api_key else {},
            timeout=5,
        )
        return resp.status_code in (200, 401, 403)
    except Exception:
        return False


def _upload_apk(
    apk_path: Path, url: str, api_key: str | None
) -> dict | None:
    """Upload APK to MobSF. Returns upload response with hash."""
    headers = {}
    if api_key:
        headers["Authorization"] = api_key
    try:
        with open(apk_path, "rb") as f:
            resp = requests.post(
                f"{url}/api/v1/upload",
                headers=headers,
                files={"file": (apk_path.name, f, "application/octet-stream")},
                timeout=MOBSF_UPLOAD_TIMEOUT,
            )
        if resp.status_code == 200:
            return resp.json()
        logger.warning(f"MobSF upload failed: {resp.status_code} {resp.text[:200]}")
    except Exception as e:
        logger.warning(f"MobSF upload error: {e}")
    return None


def _trigger_scan(
    apk_hash: str, url: str, api_key: str | None
) -> bool:
    """Trigger MobSF scan. Returns True if scan started."""
    headers = {}
    if api_key:
        headers["Authorization"] = api_key
    try:
        resp = requests.post(
            f"{url}/api/v1/scan",
            headers=headers,
            data={"hash": apk_hash},
            timeout=10,
        )
        return resp.status_code == 200
    except Exception as e:
        logger.warning(f"MobSF scan trigger error: {e}")
    return False


def _wait_for_scan(
    apk_hash: str, url: str, api_key: str | None,
    timeout: int = MOBSF_SCAN_TIMEOUT, on_progress=None,
) -> bool:
    """Wait for MobSF scan to complete by polling report endpoint."""
    headers = {}
    if api_key:
        headers["Authorization"] = api_key
    start = time.time()
    while time.time() - start < timeout:
        try:
            resp = requests.get(
                f"{url}/api/v1/report_json",
                headers=headers,
                params={"hash": apk_hash},
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json()
                if "error" not in data:
                    return True
            if on_progress:
                elapsed = int(time.time() - start)
                on_progress(min(elapsed / timeout * 100, 95),
                            f"MobSF scanning... ({elapsed}s)")
        except Exception:
            pass
        time.sleep(3)
    return False


def _get_report(
    apk_hash: str, url: str, api_key: str | None
) -> dict | None:
    """Get MobSF JSON report."""
    headers = {}
    if api_key:
        headers["Authorization"] = api_key
    try:
        resp = requests.get(
            f"{url}/api/v1/report_json",
            headers=headers,
            params={"hash": apk_hash},
            timeout=MOBSF_REPORT_TIMEOUT,
        )
        if resp.status_code == 200:
            return resp.json()
    except Exception as e:
        logger.warning(f"MobSF report error: {e}")
    return None


def _delete_scan(
    apk_hash: str, url: str, api_key: str | None
) -> None:
    """Clean up scan from MobSF."""
    headers = {}
    if api_key:
        headers["Authorization"] = api_key
    try:
        requests.post(
            f"{url}/api/v1/delete_scan",
            headers=headers,
            data={"hash": apk_hash},
            timeout=10,
        )
    except Exception:
        pass


def _parse_permissions(report: dict) -> tuple[list[dict], list[dict]]:
    """Parse permissions from MobSF report."""
    all_perms = []
    dangerous = []
    permissions_data = report.get("permissions", {})
    if isinstance(permissions_data, dict):
        for perm_list in permissions_data.values():
            if isinstance(perm_list, list):
                for perm in perm_list:
                    if isinstance(perm, str):
                        perm_info = {"name": perm}
                        all_perms.append(perm_info)
                        if perm in DANGEROUS_PERMISSION_GROUPS:
                            dangerous.append({
                                "name": perm,
                                "group": DANGEROUS_PERMISSION_GROUPS[perm],
                            })
                    elif isinstance(perm, dict):
                        name = perm.get("name", perm.get("permission", ""))
                        all_perms.append({"name": name, **perm})
                        if name in DANGEROUS_PERMISSION_GROUPS:
                            dangerous.append({
                                "name": name,
                                "group": DANGEROUS_PERMISSION_GROUPS[name],
                                **perm,
                            })
    return all_perms, dangerous


def _parse_components(report: dict) -> dict:
    """Parse activities, services, receivers, providers."""
    components = {
        "activities": [],
        "services": [],
        "receivers": [],
        "providers": [],
    }
    for key in ("activities", "activity_aliases"):
        act_list = report.get(key, [])
        if isinstance(act_list, list):
            components["activities"].extend(
                a if isinstance(a, str) else str(a) for a in act_list
            )
    for key in ("services",):
        svc_list = report.get(key, [])
        if isinstance(svc_list, list):
            components["services"].extend(
                s if isinstance(s, str) else str(s) for s in svc_list
            )
    for key in ("receivers",):
        rcv_list = report.get(key, [])
        if isinstance(rcv_list, list):
            components["receivers"].extend(
                r if isinstance(r, str) else str(r) for r in rcv_list
            )
    for key in ("providers",):
        prv_list = report.get(key, [])
        if isinstance(prv_list, list):
            components["providers"].extend(
                p if isinstance(p, str) else str(p) for p in prv_list
            )
    return components


def _parse_certificate(report: dict) -> dict:
    """Parse certificate information."""
    cert_info = {}
    for key in ("certificate_info", "cert_info", "apk_certificate"):
        if key in report:
            data = report[key]
            if isinstance(data, dict):
                cert_info = data
                break
            elif isinstance(data, list) and data:
                cert_info = data[0] if isinstance(data[0], dict) else {"raw": data}
                break
    return cert_info


def _check_certificate_verified(report: dict) -> bool:
    """Check if APK certificate is verified/valid."""
    for key in ("certificate_verified", "cert_verified", "signature_verified"):
        if key in report:
            return bool(report[key])
    cert = _parse_certificate(report)
    if cert:
        issuer = cert.get("issuer", cert.get("issuerDN", ""))
        subject = cert.get("subject", cert.get("subjectDN", ""))
        if issuer and subject and issuer != subject:
            return True
    return False


def _parse_network(report: dict) -> tuple[list[str], list[str], list[str]]:
    """Parse URLs, domains, IPs from report."""
    urls = []
    domains = []
    ips = []

    for key in ("urls", "extracted_urls", "dominated_urls"):
        url_list = report.get(key, [])
        if isinstance(url_list, list):
            urls.extend(str(u) for u in url_list if u)

    for key in ("domains", "extracted_domains"):
        dom_list = report.get(key, [])
        if isinstance(dom_list, list):
            domains.extend(str(d) for d in dom_list if d)

    for key in ("ips", "extracted_ips"):
        ip_list = report.get(key, [])
        if isinstance(ip_list, list):
            ips.extend(str(i) for i in ip_list if i)

    return urls, domains, ips


def _parse_code_analysis(report: dict) -> list[dict]:
    """Parse code analysis findings."""
    findings = []
    for key in ("code_analysis", "code_analysis_findings"):
        ca = report.get(key, {})
        if isinstance(ca, dict):
            for category, items in ca.items():
                if isinstance(items, list):
                    for item in items:
                        if isinstance(item, dict):
                            findings.append({
                                "category": category,
                                "title": item.get("title", item.get("name", "")),
                                "severity": item.get("severity", "info"),
                                "description": item.get("description", item.get("details", "")),
                                "file": item.get("file", ""),
                                "line": item.get("line", 0),
                            })
                        elif isinstance(item, str):
                            findings.append({
                                "category": category,
                                "title": item,
                                "severity": "info",
                            })
    return findings


def _parse_secrets(report: dict) -> list[dict]:
    """Parse hardcoded secrets from report."""
    secrets = []
    for key in ("secrets", "hardcoded_secrets", "secret_codes"):
        sec_list = report.get(key, [])
        if isinstance(sec_list, list):
            for sec in sec_list:
                if isinstance(sec, dict):
                    secrets.append({
                        "type": sec.get("type", sec.get("name", "unknown")),
                        "severity": sec.get("severity", "high"),
                        "file": sec.get("file", ""),
                        "line": sec.get("line", 0),
                        "description": sec.get("description", sec.get("details", "")),
                    })
    return secrets


def _parse_manifest_analysis(report: dict) -> tuple[list[dict], list[str]]:
    """Parse manifest analysis and malware permissions."""
    manifest_findings = []
    malware_perms = []

    for key in ("manifest_analysis", "manifest"):
        ma = report.get(key, {})
        if isinstance(ma, dict):
            for finding in ma.get("findings", []):
                if isinstance(finding, dict):
                    manifest_findings.append(finding)
            for perm in ma.get("malware_permissions", []):
                if isinstance(perm, str):
                    malware_perms.append(perm)

    return manifest_findings, malware_perms


def _detect_spyware(package_name: str, activities: list[str],
                     services: list[str]) -> list[str]:
    """Detect known spyware packages."""
    detected = []
    if package_name in KNOWN_SPYWARE_PACKAGES:
        detected.append(package_name)
    return detected


def _compute_appsec_score(dangerous_perms: list[dict], secrets: list[dict],
                          code_findings: list[dict], spyware: list[str]) -> tuple[float, str]:
    """Compute AppSec score and highest risk level."""
    score = 100.0

    score -= len(dangerous_perms) * 2.0
    score -= len(secrets) * 10.0
    score -= len(spyware) * 30.0

    critical_count = sum(
        1 for f in code_findings
        if f.get("severity", "").lower() in ("critical", "high")
    )
    score -= critical_count * 5.0

    score = max(0.0, min(100.0, score))

    if spyware:
        risk = "critical"
    elif score < 50:
        risk = "high"
    elif score < 75:
        risk = "medium"
    elif score < 90:
        risk = "low"
    else:
        risk = "info"

    return score, risk


def analyze_apk(
    apk_path: Path,
    url: str = None,
    api_key: str | None = None,
    on_progress=None,
    cleanup: bool = False,
) -> MobSFResult:
    """Run full MobSF analysis on an APK file.

    Workflow: Upload → Scan → Wait → Report → Parse

    Args:
        apk_path: Path to APK file
        url: MobSF server URL (default: http://localhost:8000)
        api_key: MobSF API key (from env or config)
        on_progress: Progress callback(percent, message)
        cleanup: Delete scan from MobSF after reporting

    Returns:
        MobSFResult with parsed findings
    """
    result = MobSFResult()

    if url is None or api_key is None:
        cfg_url, cfg_key = _get_mobsf_config()
        if url is None:
            url = cfg_url
        if api_key is None:
            api_key = cfg_key

    if not apk_path.exists():
        result.details = f"APK not found: {apk_path}"
        return result

    if not check_mobsf_available(url, api_key):
        result.details = (
            "MobSF not available. Run: "
            "docker run -p 8000:8000 opensecurity/mobile-security-framework-mobsf"
        )
        logger.warning("MobSF not available — skipping MobSF analysis")
        return result

    result.available = True
    apk_md5 = None

    try:
        if on_progress:
            on_progress(5, f"Uploading {apk_path.name} to MobSF...")

        upload_resp = _upload_apk(apk_path, url, api_key)
        if not upload_resp or "hash" not in upload_resp:
            result.details = "MobSF upload failed"
            return result

        apk_md5 = upload_resp["hash"]
        result.apk_name = upload_resp.get("file_name", apk_path.name)

        if on_progress:
            on_progress(15, f"Uploaded. Hash: {apk_md5[:12]}... Triggering scan...")

        if not _trigger_scan(apk_md5, url, api_key):
            result.details = "MobSF scan trigger failed"
            return result

        if on_progress:
            on_progress(20, "MobSF scan started. Waiting for completion...")

        if not _wait_for_scan(apk_md5, url, api_key, on_progress=on_progress):
            result.details = "MobSF scan timed out"
            return result

        if on_progress:
            on_progress(90, "Retrieving MobSF report...")

        report = _get_report(apk_md5, url, api_key)
        if not report:
            result.details = "Failed to retrieve MobSF report"
            return result

        result.package_name = report.get("package_name", "")
        result.version_name = report.get("version_name", "")
        result.version_code = int(report.get("version_code", 0))
        result.target_sdk = int(report.get("target_sdk", 0))
        result.min_sdk = int(report.get("min_sdk", 0))

        result.permissions, result.dangerous_permissions = _parse_permissions(report)
        components = _parse_components(report)
        result.activities = components["activities"]
        result.services = components["services"]
        result.receivers = components["receivers"]
        result.providers = components["providers"]

        result.certificate_info = _parse_certificate(report)
        result.certificate_verified = _check_certificate_verified(report)

        result.code_analysis = _parse_code_analysis(report)
        result.secrets = _parse_secrets(report)

        result.urls, result.domains, result.ips = _parse_network(report)

        result.manifest_analysis, result.manifest_malware_perms = (
            _parse_manifest_analysis(report)
        )

        result.spyware_detected = _detect_spyware(
            result.package_name, result.activities, result.services
        )

        result.appsec_score, result.highest_risk = _compute_appsec_score(
            result.dangerous_permissions, result.secrets,
            result.code_analysis, result.spyware_detected,
        )

        findings_count = (
            len(result.dangerous_permissions) + len(result.secrets)
            + len(result.spyware_detected) + len(result.manifest_malware_perms)
        )
        result.details = (
            f"MobSF analysis complete: {findings_count} findings, "
            f"AppSec score: {result.appsec_score:.1f}/100"
        )

        if on_progress:
            on_progress(100, result.details)

    except Exception as e:
        result.details = f"MobSF analysis failed: {e}"
        logger.warning(result.details)

    finally:
        if cleanup and apk_md5:
            _delete_scan(apk_md5, url, api_key)

    return result
