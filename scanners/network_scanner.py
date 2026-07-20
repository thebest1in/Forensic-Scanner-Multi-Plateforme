import subprocess
import json
from pathlib import Path
from datetime import datetime

from core.base_scanner import BaseScanner, ScanResult
from core.scanner_registry import ScannerRegistry


@ScannerRegistry.register
class NetworkScanner(BaseScanner):
    """Network traffic and infrastructure forensic scanner."""

    def __init__(self, interface: str = "", profile: str = "deep", **kwargs):
        super().__init__(name="Network Forensic Scanner", platform="network")
        self.interface = interface
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
        network_cmds = {
            "active_connections": "netstat -ano 2>/dev/null || ss -tunap 2>/dev/null",
            "listening_ports": "netstat -tlnp 2>/dev/null || ss -tlnp 2>/dev/null",
            "routing_table": "route -n 2>/dev/null || ip route show 2>/dev/null",
            "arp_cache": "arp -a 2>/dev/null || ip neigh show 2>/dev/null",
            "dns_cache": "ipconfig /displaydns 2>/dev/null || cat /etc/resolv.conf 2>/dev/null",
            "firewall_rules": "iptables -L -n -v 2>/dev/null || nft list ruleset 2>/dev/null",
            "network_interfaces": "ip addr show 2>/dev/null || ifconfig 2>/dev/null",
            "wifi_scan": "netsh wlan show networks 2>/dev/null || iwlist scan 2>/dev/null",
            "wifi_profiles": "netsh wlan show profiles 2>/dev/null || cat /etc/NetworkManager/system-connections/* 2>/dev/null",
            "process_network": "lsof -i 2>/dev/null || netstat -tlnp 2>/dev/null",
        }
        items = list(network_cmds.items())
        for i, (key, cmd) in enumerate(items):
            self._report_progress((i / len(items)) * 50, f"Collecting: {key}")
            ok, data = self._run_cmd(cmd)
            fpath = output_dir / f"{key}.txt"
            fpath.write_text(data if ok and data else f"[NO DATA] {key}", encoding="utf-8")
            artifacts.append({"id": key, "file": str(fpath), "desc": key.replace("_", " ").title(), "size": fpath.stat().st_size})
        return artifacts

    def analyze_artifacts(self, artifacts: list[dict], output_dir: Path) -> list[dict]:
        threats = []
        suspicious_ports = {4444, 5555, 1337, 31337, 6666, 6667, 8888, 9999}
        for art in artifacts:
            fpath = Path(art["file"])
            if not fpath.exists():
                continue
            try:
                content = fpath.read_text(encoding="utf-8", errors="replace")
                lines = content.split("\n")
                for line in lines:
                    for port in suspicious_ports:
                        if f":{port}" in line.lower() and ("listen" in line.lower() or "established" in line.lower()):
                            threats.append({
                                "type": "suspicious_port",
                                "indicator": f"Port {port} active",
                                "source": art["id"],
                                "severity": "suspicious",
                                "line": line.strip()[:200],
                            })
            except Exception:
                continue
        return threats

    def get_capabilities(self) -> list[str]:
        return ["packet_capture", "connection_analysis", "dns_forensics", "firewall_audit", "wifi_analysis"]
