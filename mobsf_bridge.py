import json
import time
from pathlib import Path

from core import logger, run_adb, ADB_TIMEOUT


# ============================================================
# MobSF REST API BRIDGE
# ============================================================

DEFAULT_MOBSF_URL = "http://127.0.0.1:8000"


class MobSFBridge:
    """Pull APK from device and submit to local MobSF for static analysis."""

    def __init__(self, serial: str, mobsf_url: str = DEFAULT_MOBSF_URL, api_key: str = ""):
        self._serial = serial
        self._url = mobsf_url.rstrip("/")
        self._api_key = api_key

    def _headers(self) -> dict:
        h = {"Content-Type": "application/json"}
        if self._api_key:
            h["Authorization"] = self._api_key
        return h

    def check_server(self) -> bool:
        """Check if MobSF server is reachable."""
        try:
            import requests
            resp = requests.get(f"{self._url}/api/v1/about", timeout=5, headers=self._headers())
            if resp.status_code == 200:
                logger.success(f"MobSF server reachable: {self._url}")
                return True
            logger.warning(f"MobSF server responded: {resp.status_code}")
            return False
        except Exception as e:
            logger.warning(f"MobSF server unreachable: {e}")
            return False

    def pull_apk(self, package_name: str, dump_dir: Path) -> Path | None:
        """Pull APK from device via ADB."""
        # Get APK path on device
        success, output = run_adb(
            f"-s {self._serial} shell pm path {package_name}",
            timeout=ADB_TIMEOUT,
        )
        if not success or not output:
            logger.error(f"Cannot find APK for {package_name}")
            return None

        # Parse the package path (usually "package:/data/app/...")
        apk_path = output.strip().split("\n")[0]
        if apk_path.startswith("package:"):
            apk_path = apk_path[len("package:"):]

        # Pull to local
        local_path = dump_dir / f"{package_name}.apk"
        success, _ = run_adb(
            f"-s {self._serial} pull {apk_path} {local_path}",
            timeout=120,
        )
        if success and local_path.exists():
            size_mb = local_path.stat().st_size / (1024 * 1024)
            logger.success(f"Pulled APK: {package_name} ({size_mb:.1f} MB)")
            return local_path
        else:
            logger.error(f"Failed to pull APK: {package_name}")
            return None

    def upload_and_scan(self, apk_path: Path) -> dict | None:
        """Upload APK to MobSF and return scan results."""
        try:
            import requests

            # Upload
            with open(apk_path, "rb") as f:
                resp = requests.post(
                    f"{self._url}/api/v1/upload",
                    files={"file": (apk_path.name, f, "application/vnd.android.package-archive")},
                    headers={"Authorization": self._api_key} if self._api_key else {},
                    timeout=300,
                )

            if resp.status_code != 200:
                logger.error(f"MobSF upload failed: {resp.status_code}")
                return None

            upload_data = resp.json()
            hash_val = upload_data.get("hash", "")
            if not hash_val:
                logger.error("MobSF upload returned no hash")
                return None

            # Trigger scan
            scan_resp = requests.post(
                f"{self._url}/api/v1/scan",
                data=json.dumps({"hash": hash_val}),
                headers=self._headers(),
                timeout=600,
            )

            if scan_resp.status_code != 200:
                logger.error(f"MobSF scan failed: {scan_resp.status_code}")
                return None

            # Get report
            report_resp = requests.get(
                f"{self._url}/api/v1/report_json",
                data=json.dumps({"hash": hash_val}),
                headers=self._headers(),
                timeout=60,
            )

            if report_resp.status_code == 200:
                return report_resp.json()

            return {"hash": hash_val, "status": "scan_complete", "report_status": report_resp.status_code}

        except Exception as e:
            logger.error(f"MobSF bridge error: {e}")
            return None


def analyze_package(
    serial: str,
    package_name: str,
    dump_dir: Path,
    mobsf_url: str = DEFAULT_MOBSF_URL,
    api_key: str = "",
) -> dict | None:
    """Convenience: pull APK and submit to MobSF."""
    bridge = MobSFBridge(serial, mobsf_url, api_key)

    if not bridge.check_server():
        return None

    apk_path = bridge.pull_apk(package_name, dump_dir)
    if not apk_path:
        return None

    result = bridge.upload_and_scan(apk_path)
    if result:
        # Save MobSF report
        report_path = dump_dir / f"mobsf_{package_name}.json"
        report_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
        logger.success(f"MobSF report: {report_path.name}")

    return result
