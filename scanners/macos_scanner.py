import subprocess
import os
from pathlib import Path
from datetime import datetime

from core.base_scanner import BaseScanner, ScanResult
from core.scanner_registry import ScannerRegistry


@ScannerRegistry.register
class MacOSScanner(BaseScanner):
    """macOS forensic artifact scanner."""

    MACOS_ARTIFACTS = {
        "system_info": {"desc": "System information"},
        "system_logs": {"desc": "System logs"},
        "crash_reports": {"desc": "Crash reports"},
        "unified_logs": {"desc": "Unified logging system"},
        "installed_apps": {"desc": "Installed applications"},
        "login_items": {"desc": "Login items"},
        "launch_agents": {"desc": "Launch agents"},
        "launch_daemons": {"desc": "Launch daemons"},
        "safari_history": {"desc": "Safari browsing history"},
        "chrome_data": {"desc": "Chrome browser data"},
        "firefox_data": {"desc": "Firefox browser data"},
        "wifi_profiles": {"desc": "WiFi network profiles"},
        "bluetooth_devices": {"desc": "Bluetooth paired devices"},
        "recent_items": {"desc": "Recent items"},
        "user_accounts": {"desc": "User accounts"},
        "filevault": {"desc": "FileVault status"},
        "sip_status": {"desc": "System Integrity Protection"},
        "firewall": {"desc": "Firewall configuration"},
        "network_interfaces": {"desc": "Network interfaces"},
        "routing_table": {"desc": "Routing table"},
        "dns_config": {"desc": "DNS configuration"},
        "processes": {"desc": "Running processes"},
        "open_files": {"desc": "Open files"},
        "kernel_extensions": {"desc": "Kernel extensions"},
        "profiles": {"desc": "Configuration profiles"},
    }

    def __init__(self, serial: str = "", profile: str = "deep", **kwargs):
        super().__init__(name="macOS Forensic Scanner", platform="macos")
        self.profile = profile

    def _run_cmd(self, cmd: str, timeout: int = 15) -> tuple[bool, str]:
        try:
            r = subprocess.run(
                cmd, shell=True, capture_output=True, text=True,
                timeout=timeout, encoding="utf-8", errors="replace",
            )
            return r.returncode == 0, r.stdout.strip() or r.stderr.strip()
        except Exception as e:
            return False, str(e)

    def collect_artifacts(self, target: str, output_dir: Path) -> list[dict]:
        output_dir.mkdir(parents=True, exist_ok=True)
        artifacts = []
        cmd_map = {
            "system_info": "system_profiler SPSoftwareDataType",
            "system_logs": "log show --last 1h --style compact 2>/dev/null | head -5000",
            "crash_reports": "ls -la /Library/Logs/DiagnosticReports/ 2>/dev/null; ls -la ~/Library/Logs/DiagnosticReports/ 2>/dev/null",
            "unified_logs": "log show --last 10m --info --debug 2>/dev/null | head -3000",
            "installed_apps": "ls /Applications/ 2>/dev/null; mdfind 'kMDItemKind == Application' 2>/dev/null",
            "login_items": "osascript -e 'tell application \"System Events\" to get the name of every login item' 2>/dev/null",
            "launch_agents": "ls -la /Library/LaunchAgents/ 2>/dev/null; ls -la ~/Library/LaunchAgents/ 2>/dev/null",
            "launch_daemons": "ls -la /Library/LaunchDaemons/ 2>/dev/null",
            "safari_history": "sqlite3 ~/Library/Safari/History.db 'SELECT datetime(visit_time + 978307200, \"unixepoch\"), url, title FROM history_visits ORDER BY visit_time DESC LIMIT 500' 2>/dev/null",
            "chrome_data": "ls -la ~/Library/Application\\ Support/Google/Chrome/Default/ 2>/dev/null",
            "firefox_data": "ls -la ~/Library/Application\\ Support/Firefox/Profiles/ 2>/dev/null",
            "wifi_profiles": "networksetup -listallhardwareports 2>/dev/null; networksetup -getairportnetwork en0 2>/dev/null",
            "bluetooth_devices": "system_profiler SPBluetoothDataType 2>/dev/null",
            "recent_items": "ls -la ~/Library/Recent/ 2>/dev/null",
            "user_accounts": "dscl . list /Users 2>/dev/null",
            "filevault": "fdesetup status 2>/dev/null",
            "sip_status": "csrutil status 2>/dev/null",
            "firewall": "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null",
            "network_interfaces": "ifconfig -a 2>/dev/null",
            "routing_table": "netstat -nr 2>/dev/null",
            "dns_config": "scutil --dns 2>/dev/null",
            "processes": "ps auxww 2>/dev/null",
            "open_files": "lsof 2>/dev/null | head -3000",
            "kernel_extensions": "kextstat 2>/dev/null",
            "profiles": "profiles list 2>/dev/null",
        }
        items = list(self.MACOS_ARTIFACTS.items())
        for i, (key, info) in enumerate(items):
            self._report_progress((i / len(items)) * 50, f"Collecting: {info['desc']}")
            cmd = cmd_map.get(key, f"echo '[NOT IMPLEMENTED] {key}'")
            ok, data = self._run_cmd(cmd)
            fpath = output_dir / f"{key}.txt"
            fpath.write_text(data if ok and data else f"[NO DATA] {info['desc']}", encoding="utf-8")
            artifacts.append({"id": key, "file": str(fpath), "desc": info["desc"], "size": fpath.stat().st_size})
        return artifacts

    def analyze_artifacts(self, artifacts: list[dict], output_dir: Path) -> list[dict]:
        threats = []
        mac_indicators = ["xprotect", "malware", "adware", "trojan", "backdoor", "keylogger"]
        for art in artifacts:
            fpath = Path(art["file"])
            if not fpath.exists():
                continue
            try:
                content = fpath.read_text(encoding="utf-8", errors="replace").lower()
                for ind in mac_indicators:
                    if ind in content:
                        threats.append({
                            "type": "macos_malware_indicator",
                            "indicator": ind,
                            "source": art["id"],
                            "severity": "suspicious",
                        })
            except Exception:
                continue
        return threats

    def get_capabilities(self) -> list[str]:
        return ["system_profiling", "log_analysis", "browser_forensics", "malware_detection", "persistence_detection"]
