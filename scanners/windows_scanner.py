import os
import json
import hashlib
from pathlib import Path
from datetime import datetime

from core.base_scanner import BaseScanner, ScanResult
from core.scanner_registry import ScannerRegistry


@ScannerRegistry.register
class WindowsScanner(BaseScanner):
    """Windows forensic artifact scanner."""

    WINDOWS_ARTIFACTS = {
        "event_logs": {
            "paths": [
                "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx",
                "C:\\Windows\\System32\\winevt\\Logs\\System.evtx",
                "C:\\Windows\\System32\\winevt\\Logs\\Application.evtx",
            ],
            "desc": "Windows Event Logs",
        },
        "prefetch": {
            "paths": ["C:\\Windows\\Prefetch\\*.pf"],
            "desc": "Prefetch files",
        },
        "amcache": {
            "paths": ["C:\\Windows\\appcompat\\Programs\\Amcache.hve"],
            "desc": "Amcache registry",
        },
        "registry_sam": {
            "paths": ["C:\\Windows\\System32\\config\\SAM"],
            "desc": "SAM database",
        },
        "registry_software": {
            "paths": ["C:\\Windows\\System32\\config\\SOFTWARE"],
            "desc": "SOFTWARE registry",
        },
        "registry_system": {
            "paths": ["C:\\Windows\\System32\\config\\SYSTEM"],
            "desc": "SYSTEM registry",
        },
        "browser_chrome": {
            "paths": [
                "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\History",
                "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Cookies",
            ],
            "desc": "Chrome browser data",
        },
        "browser_edge": {
            "paths": [
                "%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\History",
            ],
            "desc": "Edge browser data",
        },
        "recent_files": {
            "paths": ["%APPDATA%\\Microsoft\\Windows\\Recent\\*.lnk"],
            "desc": "Recent file shortcuts",
        },
        "jump_lists": {
            "paths": ["%APPDATA%\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\*"],
            "desc": "Jump lists",
        },
        "temp_files": {
            "paths": ["%TEMP%\\*"],
            "desc": "Temporary files",
        },
        " recycle_bin": {
            "paths": ["C:\\$Recycle.Bin\\*"],
            "desc": "Recycle Bin",
        },
        "startup": {
            "paths": [
                "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*",
                "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*",
            ],
            "desc": "Startup programs",
        },
        "installed_software": {
            "paths": ["HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*"],
            "desc": "Installed software registry",
        },
        "network_profiles": {
            "paths": ["C:\\ProgramData\\Microsoft\\Wlansvc\\Profiles\\*"],
            "desc": "WiFi profiles",
        },
        "dns_cache": {
            "desc": "DNS resolver cache",
        },
        "arp_table": {
            "desc": "ARP cache table",
        },
        "running_processes": {
            "desc": "Running processes",
        },
        "open_connections": {
            "desc": "Network connections",
        },
        "scheduled_tasks": {
            "desc": "Scheduled tasks",
        },
        "services": {
            "desc": "Windows services",
        },
    }

    def __init__(self, serial: str = "", profile: str = "deep", **kwargs):
        super().__init__(name="Windows Forensic Scanner", platform="windows")
        self.profile = profile

    def collect_artifacts(self, target: str, output_dir: Path) -> list[dict]:
        output_dir.mkdir(parents=True, exist_ok=True)
        artifacts = []
        items = list(self.WINDOWS_ARTIFACTS.items())
        for i, (key, info) in enumerate(items):
            self._report_progress((i / len(items)) * 50, f"Collecting: {info['desc']}")
            fpath = output_dir / f"{key}.txt"
            try:
                if "paths" in info:
                    self._collect_paths(info["paths"], fpath)
                else:
                    self._collect_live_data(key, fpath)
                if fpath.exists():
                    artifacts.append({"id": key, "file": str(fpath), "desc": info["desc"], "size": fpath.stat().st_size})
            except Exception as e:
                fpath.write_text(f"[ERROR] {e}", encoding="utf-8")
                artifacts.append({"id": key, "file": str(fpath), "desc": info["desc"], "size": 0, "error": str(e)})
        return artifacts

    def _collect_paths(self, patterns: list[str], output: Path):
        lines = []
        for pattern in patterns:
            expanded = os.path.expandvars(pattern)
            from glob import glob
            for match in glob(expanded):
                p = Path(match)
                if p.exists():
                    stat = p.stat()
                    lines.append(f"{p} | Size: {stat.st_size} | Modified: {datetime.fromtimestamp(stat.st_mtime)}")
        output.write_text("\n".join(lines) if lines else "[NO FILES FOUND]", encoding="utf-8")

    def _collect_live_data(self, key: str, output: Path):
        import subprocess
        cmd_map = {
            "dns_cache": "ipconfig /displaydns",
            "arp_table": "arp -a",
            "running_processes": "tasklist /v /fo csv",
            "open_connections": "netstat -ano",
            "scheduled_tasks": "schtasks /query /fo csv /v",
            "services": "sc query type= all",
        }
        cmd = cmd_map.get(key, "")
        if cmd:
            try:
                r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15, encoding="utf-8", errors="replace")
                output.write_text(r.stdout or r.stderr or "[EMPTY]", encoding="utf-8")
            except Exception as e:
                output.write_text(f"[ERROR] {e}", encoding="utf-8")
        else:
            output.write_text("[NOT IMPLEMENTED]", encoding="utf-8")

    def analyze_artifacts(self, artifacts: list[dict], output_dir: Path) -> list[dict]:
        threats = []
        suspicious = ["mimikatz", "lazagne", "bloodhound", "cobaltstrike", "meterpreter", "empire", "covenant"]
        for art in artifacts:
            fpath = Path(art["file"])
            if not fpath.exists():
                continue
            try:
                content = fpath.read_text(encoding="utf-8", errors="replace").lower()
                for ind in suspicious:
                    if ind in content:
                        threats.append({
                            "type": "windows_malware_indicator",
                            "indicator": ind,
                            "source": art["id"],
                            "severity": "critical",
                        })
            except Exception:
                continue
        return threats

    def get_capabilities(self) -> list[str]:
        return ["registry_analysis", "event_log_parsing", "browser_forensics", "malware_detection", "live_acquisition"]
