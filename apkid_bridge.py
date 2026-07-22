import re
import subprocess
import json
from pathlib import Path
from dataclasses import dataclass, field

from core import logger, run_adb, ADB_TIMEOUT


# ============================================================
# APKiD PACKER / OBFUSCATION DETECTION
# ============================================================

# Dangerous permissions that, combined with packing, indicate malware
_DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.READ_CALL_LOG",
    "android.permission.READ_PHONE_STATE",
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.WRITE_SETTINGS",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.INTERNET",
    "android.permission.INSTALL_PACKAGES",
    "android.permission.DELETE_PACKAGES",
}

# Known packers / protectors detected by APKiD
_PACKER_NAMES = {
    "dexguard", "secshell", "ijiami", "bangcle", "legu",
    "qihoo", "tencent", "alibaba", "baidu", "netease",
    "apkprotector", "apkshield", "dexprotector", "stringer",
    "apportable", "artiwall", "zhili", "sodalite",
    "allyoudo", "apkmirror", "obfuse",
}

# Anti-analysis techniques
_ANTI_ANALYSIS = {
    "debugger detection", "emulator detection", "root detection",
    "hook detection", "integrity check", "ptrace",
    "frida detection", "xposed detection", "substrate detection",
}


@dataclass
class APKiDResult:
    """Result of APKiD analysis on a single APK."""
    package_name: str = ""
    apk_path: str = ""
    packers_found: list[str] = field(default_factory=list)
    anti_analysis: list[str] = field(default_factory=list)
    compiler: str = ""
    dex_count: int = 0
    obfuscated: bool = False
    dangerous_permissions: list[str] = field(default_factory=list)
    risk_score: int = 0  # 0-100
    threat_level: str = "CLEAN"

    def to_dict(self) -> dict:
        return {
            "package_name": self.package_name,
            "apk_path": self.apk_path,
            "packers_found": self.packers_found,
            "anti_analysis": self.anti_analysis,
            "compiler": self.compiler,
            "dex_count": self.dex_count,
            "obfuscated": self.obfuscated,
            "dangerous_permissions": self.dangerous_permissions,
            "risk_score": self.risk_score,
            "threat_level": self.threat_level,
        }


class APKiDBridge:
    """Detect packers, obfuscation, and anti-analysis in Android APKs.

    Uses APKiD (RedNaga) — a tool that identifies Packers, Protectors,
    Obfuscators, and Compiler fingerprints from DEX files.
    """

    def __init__(self, serial: str = ""):
        self._serial = serial
        self._apkid_path = self._find_apkid()

    @staticmethod
    def check_apkid_available() -> bool:
        """Check if APKiD is installed and accessible."""
        try:
            result = subprocess.run(
                ["apkid", "--version"],
                capture_output=True, text=True, timeout=10,
                encoding="utf-8", errors="replace",
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def _find_apkid(self) -> str:
        """Locate the APKiD executable."""
        try:
            result = subprocess.run(
                ["apkid", "--version"],
                capture_output=True, text=True, timeout=10,
                encoding="utf-8", errors="replace",
            )
            if result.returncode == 0:
                return "apkid"
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return ""

    def scan_apk(self, apk_path: Path) -> APKiDResult:
        """Run APKiD against a single APK file."""
        result = APKiDResult(apk_path=str(apk_path))

        if not self._apkid_path:
            logger.warning("APKiD not available — skipping packer detection")
            return result

        if not apk_path.exists():
            logger.warning(f"APK not found: {apk_path}")
            return result

        result.package_name = apk_path.stem
        try:
            output = subprocess.run(
                [self._apkid_path, "--output", "json", str(apk_path)],
                capture_output=True, text=True, timeout=120,
                encoding="utf-8", errors="replace",
            )
            if output.returncode == 0 and output.stdout.strip():
                self._parse_apkid_output(output.stdout, result)
            else:
                logger.warning(f"APKiD returned non-zero for {apk_path.name}: {output.stderr[:200]}")
        except subprocess.TimeoutExpired:
            logger.warning(f"APKiD timed out on {apk_path.name}")
        except Exception as e:
            logger.error(f"APKiD scan failed for {apk_path.name}: {e}")

        result.risk_score = self._compute_risk(result)
        result.threat_level = self._score_to_threat(result.risk_score)

        if result.risk_score > 0:
            logger.warning(
                f"APKiD: {result.package_name} -> risk={result.risk_score} "
                f"({result.threat_level}) packers={result.packers_found}"
            )
        return result

    def scan_directory(self, directory: Path) -> list[APKiDResult]:
        """Scan all APKs in a directory."""
        results = []
        apk_files = list(directory.rglob("*.apk"))
        if not apk_files:
            logger.info(f"No APK files found in {directory}")
            return results

        logger.info(f"APKiD: scanning {len(apk_files)} APKs in {directory.name}")
        for apk in apk_files:
            results.append(self.scan_apk(apk))
        return results

    def scan_from_device(self, package_name: str) -> APKiDResult:
        """Pull an APK from the connected device and scan it."""
        result = APKiDResult(package_name=package_name)

        if not self._serial or not self._apkid_path:
            return result

        success, output = run_adb(
            f"-s {self._serial} shell pm path {package_name}",
            timeout=10,
        )
        if not success or not output:
            logger.warning(f"Cannot get APK path for {package_name}")
            return result

        remote_path = output.strip().split("\n")[0].replace("package:", "")
        local_dir = Path("dump_forensic") / "apkid_cache"
        local_dir.mkdir(exist_ok=True)
        local_apk = local_dir / f"{package_name.split('.')[-1]}.apk"

        success, _ = run_adb(
            f"-s {self._serial} pull {remote_path} {local_apk}",
            timeout=30,
        )
        if success and local_apk.exists():
            result = self.scan_apk(local_apk)
            result.package_name = package_name
        return result

    def _parse_apkid_output(self, output: str, result: APKiDResult):
        """Parse APKiD JSON output into APKiDResult."""
        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            return

        for filename, info in data.items():
            if not isinstance(info, dict):
                continue
            for section in ("detection", "packers", "anti_analysis", "compilers"):
                findings = info.get(section, [])
                if isinstance(findings, dict):
                    findings = list(findings.values()) if findings else []
                if not isinstance(findings, list):
                    continue
                for item in findings:
                    name = str(item).lower()
                    if section == "packers" or any(p in name for p in _PACKER_NAMES):
                        result.packers_found.append(str(item))
                    elif section == "anti_analysis" or any(a in name for a in _ANTI_ANALYSIS):
                        result.anti_analysis.append(str(item))
                    elif section == "compilers":
                        result.compiler = str(item)
            dex = info.get("dex", [])
            if isinstance(dex, list):
                result.dex_count = len(dex)
            elif isinstance(dex, int):
                result.dex_count = dex
            result.obfuscated = bool(result.packers_found or result.anti_analysis)

    def _compute_risk(self, result: APKiDResult) -> int:
        """Compute 0-100 risk score based on packer + anti-analysis findings."""
        score = 0
        if result.packers_found:
            score += 25 * min(len(result.packers_found), 3)
        if result.anti_analysis:
            score += 20 * min(len(result.anti_analysis), 3)
        if result.obfuscated:
            score += 15
        if result.dangerous_permissions:
            score += 10 * min(len(result.dangerous_permissions), 3)
        return min(score, 100)

    @staticmethod
    def _score_to_threat(score: int) -> str:
        if score >= 70:
            return "CRITICAL"
        if score >= 40:
            return "SUSPICIOUS"
        return "CLEAN"
