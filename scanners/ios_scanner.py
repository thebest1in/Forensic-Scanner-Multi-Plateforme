import subprocess
import json
from pathlib import Path

from core.base_scanner import BaseScanner, ScanResult
from core.scanner_registry import ScannerRegistry


@ScannerRegistry.register
class IOSScanner(BaseScanner):
    """iOS device forensic scanner via pymobiledevice3."""

    IOS_ARTIFACTS = {
        "device_info": {"desc": "Device information"},
        "installed_apps": {"desc": "Installed applications"},
        "accounts": {"desc": "Apple accounts"},
        "contacts": {"desc": "Contact database"},
        "sms_messages": {"desc": "iMessage/SMS database"},
        "call_log": {"desc": "Call history"},
        "safari_history": {"desc": "Safari browsing history"},
        "photos": {"desc": "Photo library metadata"},
        "location": {"desc": "Location services data"},
        "notifications": {"desc": "Notification history"},
        "wifi_profiles": {"desc": "WiFi network profiles"},
        "bluetooth_paired": {"desc": "Bluetooth paired devices"},
        "keychain": {"desc": "Keychain metadata"},
        "backup_info": {"desc": "Backup information"},
    }

    def __init__(self, serial: str = "", profile: str = "deep", **kwargs):
        super().__init__(name="iOS Forensic Scanner", platform="ios")
        self.serial = serial
        self.profile = profile

    def _run_pymobile(self, cmd: str) -> tuple[bool, str]:
        try:
            import pymobiledevice3
            result = subprocess.run(
                ["python", "-m", "pymobiledevice3"] + cmd.split(),
                capture_output=True, text=True, timeout=30,
                encoding="utf-8", errors="replace",
            )
            return result.returncode == 0, result.stdout.strip()
        except ImportError:
            return False, "pymobiledevice3 not installed"
        except Exception as e:
            return False, str(e)

    def collect_artifacts(self, target: str, output_dir: Path) -> list[dict]:
        output_dir.mkdir(parents=True, exist_ok=True)
        artifacts = []
        items = list(self.IOS_ARTIFACTS.items())
        for i, (key, info) in enumerate(items):
            self._report_progress((i / len(items)) * 50, f"Collecting: {info['desc']}")
            ok, data = self._run_pymobile(f"developer --mode usb")
            fpath = output_dir / f"{key}.txt"
            if ok and data:
                fpath.write_text(data, encoding="utf-8", errors="replace")
                artifacts.append({"id": key, "file": str(fpath), "desc": info["desc"], "size": fpath.stat().st_size})
            else:
                fpath.write_text(f"[NOT AVAILABLE] {info['desc']}", encoding="utf-8")
                artifacts.append({"id": key, "file": str(fpath), "desc": info["desc"], "size": 0, "unavailable": True})
        return artifacts

    def analyze_artifacts(self, artifacts: list[dict], output_dir: Path) -> list[dict]:
        threats = []
        ios_indicators = ["pegasus", "pegasus spyware", "zero-click", "trident exploit"]
        for art in artifacts:
            fpath = Path(art["file"])
            if not fpath.exists():
                continue
            try:
                content = fpath.read_text(encoding="utf-8", errors="replace").lower()
                for indicator in ios_indicators:
                    if indicator in content:
                        threats.append({
                            "type": "ios_spyware",
                            "indicator": indicator,
                            "source": art["id"],
                            "severity": "critical",
                        })
            except Exception:
                continue
        return threats

    def get_capabilities(self) -> list[str]:
        return ["ios_backup", "app_analysis", "keychain_dump", "spyware_detection"]
