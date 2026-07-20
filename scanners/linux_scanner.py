import subprocess
from pathlib import Path

from core.base_scanner import BaseScanner, ScanResult
from core.scanner_registry import ScannerRegistry


@ScannerRegistry.register
class LinuxScanner(BaseScanner):
    """Linux forensic artifact scanner."""

    LINUX_ARTIFACTS = {
        "system_info": {"desc": "System information"},
        "kernel_logs": {"desc": "Kernel logs"},
        "syslog": {"desc": "System log"},
        "auth_log": {"desc": "Authentication log"},
        "installed_packages": {"desc": "Installed packages"},
        "running_services": {"desc": "Running services"},
        "cron_jobs": {"desc": "Cron jobs"},
        "processes": {"desc": "Running processes"},
        "network_interfaces": {"desc": "Network interfaces"},
        "routing_table": {"desc": "Routing table"},
        "dns_config": {"desc": "DNS configuration"},
        "open_files": {"desc": "Open files"},
        "users_and_groups": {"desc": "Users and groups"},
        "ssh_keys": {"desc": "SSH authorized keys"},
        "bash_history": {"desc": "Bash history"},
        "environment_vars": {"desc": "Environment variables"},
        "kernel_modules": {"desc": "Loaded kernel modules"},
        "mount_points": {"desc": "Mount points"},
        "iptables": {"desc": "Firewall rules"},
        "docker_containers": {"desc": "Docker containers"},
        "sudo_log": {"desc": "Sudo usage log"},
        "login_history": {"desc": "Login history"},
    }

    def __init__(self, serial: str = "", profile: str = "deep", **kwargs):
        super().__init__(name="Linux Forensic Scanner", platform="linux")
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
            "system_info": "uname -a; cat /etc/os-release 2>/dev/null; uptime",
            "kernel_logs": "dmesg 2>/dev/null | tail -500",
            "syslog": "tail -2000 /var/log/syslog 2>/dev/null || tail -2000 /var/log/messages 2>/dev/null",
            "auth_log": "tail -2000 /var/log/auth.log 2>/dev/null || tail -2000 /var/log/secure 2>/dev/null",
            "installed_packages": "dpkg -l 2>/dev/null || rpm -qa 2>/dev/null || apk list --installed 2>/dev/null",
            "running_services": "systemctl list-units --type=service --all 2>/dev/null || service --status-all 2>/dev/null",
            "cron_jobs": "crontab -l 2>/dev/null; ls -la /etc/cron* 2>/dev/null",
            "processes": "ps auxwwf 2>/dev/null",
            "network_interfaces": "ip addr show 2>/dev/null || ifconfig -a 2>/dev/null",
            "routing_table": "ip route show 2>/dev/null || route -n 2>/dev/null",
            "dns_config": "cat /etc/resolv.conf 2>/dev/null",
            "open_files": "lsof 2>/dev/null | head -3000",
            "users_and_groups": "cat /etc/passwd 2>/dev/null; cat /etc/group 2>/dev/null",
            "ssh_keys": "find / -name authorized_keys -o -name authorized_keys2 2>/dev/null | head -50",
            "bash_history": "cat ~/.bash_history 2>/dev/null | tail -500",
            "environment_vars": "env 2>/dev/null",
            "kernel_modules": "lsmod 2>/dev/null",
            "mount_points": "mount 2>/dev/null; df -h 2>/dev/null",
            "iptables": "iptables -L -n 2>/dev/null || nft list ruleset 2>/dev/null",
            "docker_containers": "docker ps -a 2>/dev/null || echo '[Docker not available]'",
            "sudo_log": "grep sudo /var/log/auth.log 2>/dev/null | tail -200 || grep sudo /var/log/secure 2>/dev/null | tail -200",
            "login_history": "last -50 2>/dev/null; lastb -20 2>/dev/null",
        }
        items = list(self.LINUX_ARTIFACTS.items())
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
        linux_indicators = ["rootkit", "backdoor", "reverse shell", "netcat", "nc -e", "cryptominer", "xmrig"]
        for art in artifacts:
            fpath = Path(art["file"])
            if not fpath.exists():
                continue
            try:
                content = fpath.read_text(encoding="utf-8", errors="replace").lower()
                for ind in linux_indicators:
                    if ind in content:
                        threats.append({
                            "type": "linux_malware_indicator",
                            "indicator": ind,
                            "source": art["id"],
                            "severity": "critical",
                        })
            except Exception:
                continue
        return threats

    def get_capabilities(self) -> list[str]:
        return ["system_profiling", "log_analysis", "process_analysis", "network_forensics", "malware_detection"]
