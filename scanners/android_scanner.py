import subprocess
import shutil
from pathlib import Path

from core.base_scanner import BaseScanner, ScanResult
from core.scanner_registry import ScannerRegistry


@ScannerRegistry.register
class AndroidScanner(BaseScanner):
    """Android device forensic scanner via ADB."""

    ANDROID_ARTIFACTS = {
        "system_log": {"cmd": "shell cat /proc/last_kmsg", "file": "last_kmsg.txt", "desc": "Last kernel log"},
        "event_log": {"cmd": "shell logcat -d -b events", "file": "event_log.txt", "desc": "Android event log"},
        "system_info": {"cmd": "shell getprop", "file": "system_properties.txt", "desc": "System properties"},
        "installed_packages": {"cmd": "shell pm list packages -f", "file": "packages.txt", "desc": "Installed packages"},
        "process_list": {"cmd": "shell ps -A", "file": "process_list.txt", "desc": "Running processes"},
        "network_info": {"cmd": "shell ip addr show", "file": "network_config.txt", "desc": "Network configuration"},
        "battery_info": {"cmd": "shell dumpsys battery", "file": "battery_info.txt", "desc": "Battery status"},
        "wifi_info": {"cmd": "shell dumpsys wifi", "file": "wifi_info.txt", "desc": "WiFi connections"},
        "bluetooth_info": {"cmd": "shell dumpsys bluetooth_manager", "file": "bluetooth_info.txt", "desc": "Bluetooth info"},
        "app_permissions": {"cmd": "shell dumpsys package", "file": "package_dump.txt", "desc": "Package permissions"},
        "screen_lock": {"cmd": "shell dumpsys trust", "file": "trust_info.txt", "desc": "Trust agents"},
        "user_accounts": {"cmd": "shell pm list users", "file": "user_accounts.txt", "desc": "User accounts"},
        "clipboard": {"cmd": "shell service call clipboard", "file": "clipboard_raw.txt", "desc": "Clipboard data"},
        "sms_messages": {"cmd": "shell content query --uri content://sms", "file": "sms_dump.txt", "desc": "SMS messages"},
        "call_log": {"cmd": "shell content query --uri content://call_log/calls", "file": "call_log.txt", "desc": "Call history"},
        "contacts": {"cmd": "shell content query --uri content://contacts/phones", "file": "contacts.txt", "desc": "Contacts"},
        "browser_bookmarks": {"cmd": "shell content query --uri content://browser/bookmarks", "file": "bookmarks.txt", "desc": "Browser bookmarks"},
        "location_history": {"cmd": "shell dumpsys location", "file": "location_history.txt", "desc": "Location history"},
        "startup_apps": {"cmd": "shell dumpsys alarm", "file": "alarms.txt", "desc": "Scheduled alarms"},
        "accessibility": {"cmd": "shell dumpsys accessibility", "file": "accessibility.txt", "desc": "Accessibility services"},
        "device_admin": {"cmd": "shell dumpsys device_policy", "file": "device_policy.txt", "desc": "Device admin policies"},
        "notification_log": {"cmd": "shell dumpsys notification --noredact", "file": "notifications.txt", "desc": "Notification history"},
        "usage_stats": {"cmd": "shell dumpsys usagestats", "file": "usage_stats.txt", "desc": "App usage statistics"},
    }

    def __init__(self, serial: str = "", profile: str = "deep", **kwargs):
        super().__init__(name="Android Forensic Scanner", platform="android")
        self.serial = serial
        self.profile = profile

    def _run_adb(self, cmd: str, timeout: int = 30) -> tuple[bool, str]:
        adb = shutil.which("adb")
        if not adb:
            return False, "ADB not found"
        full = [adb]
        if self.serial:
            full += ["-s", self.serial]
        full += cmd.split()
        try:
            r = subprocess.run(full, capture_output=True, text=True, timeout=timeout, encoding="utf-8", errors="replace")
            return r.returncode == 0, r.stdout.strip()
        except Exception as e:
            return False, str(e)

    def collect_artifacts(self, target: str, output_dir: Path) -> list[dict]:
        output_dir.mkdir(parents=True, exist_ok=True)
        artifacts = []
        items = list(self.ANDROID_ARTIFACTS.items())
        for i, (key, info) in enumerate(items):
            self._report_progress((i / len(items)) * 50, f"Collecting: {info['desc']}")
            ok, data = self._run_adb(info["cmd"])
            fpath = output_dir / info["file"]
            if ok and data:
                fpath.write_text(data, encoding="utf-8", errors="replace")
                artifacts.append({"id": key, "file": str(fpath), "desc": info["desc"], "size": fpath.stat().st_size})
        return artifacts

    def analyze_artifacts(self, artifacts: list[dict], output_dir: Path) -> list[dict]:
        threats = []
        suspicious_indicators = [
            "flexispy", "mspy", "pegasus", "dendroid", "sandrorat",
            "hackingteam", "finspy", "novispy", "droidjack", "reverse shell",
        ]
        for art in artifacts:
            fpath = Path(art["file"])
            if not fpath.exists():
                continue
            try:
                content = fpath.read_text(encoding="utf-8", errors="replace").lower()
                for indicator in suspicious_indicators:
                    if indicator in content:
                        threats.append({
                            "type": "spyware_indicator",
                            "indicator": indicator,
                            "source": art["id"],
                            "severity": "critical",
                        })
            except Exception:
                continue
        return threats

    def get_capabilities(self) -> list[str]:
        return ["adb_dump", "log_extraction", "app_analysis", "network_forensics", "spyware_detection"]
