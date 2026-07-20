import subprocess
from pathlib import Path
from datetime import datetime


class LogCollector:
    """System log collection for forensic analysis."""

    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _run_cmd(self, cmd: str, timeout: int = 30) -> tuple[bool, str]:
        try:
            r = subprocess.run(
                cmd, shell=True, capture_output=True, text=True,
                timeout=timeout, encoding="utf-8", errors="replace",
            )
            return r.returncode == 0, r.stdout.strip() or r.stderr.strip()
        except Exception as e:
            return False, str(e)

    def collect_event_logs(self) -> list[dict]:
        results = []
        import platform
        system = platform.system().lower()
        if system == "windows":
            logs = {
                "security": "wevtutil qe Security /c:1000 /f:text /rd:true",
                "system": "wevtutil qe System /c:1000 /f:text /rd:true",
                "application": "wevtutil qe Application /c:1000 /f:text /rd:true",
            }
        elif system == "linux":
            logs = {
                "syslog": "cat /var/log/syslog 2>/dev/null || cat /var/log/messages 2>/dev/null",
                "auth": "cat /var/log/auth.log 2>/dev/null || cat /var/log/secure 2>/dev/null",
                "kern": "dmesg 2>/dev/null",
            }
        else:
            logs = {
                "system_log": "log show --last 1h --style compact 2>/dev/null | head -5000",
            }
        for name, cmd in logs.items():
            ok, data = self._run_cmd(cmd)
            fpath = self.output_dir / f"{name}_log.txt"
            fpath.write_text(data if ok and data else f"[NO DATA] {name}", encoding="utf-8")
            results.append({"name": name, "file": str(fpath), "size": fpath.stat().st_size})
        return results

    def collect_application_logs(self) -> list[dict]:
        results = []
        import platform
        system = platform.system().lower()
        if system == "windows":
            log_dirs = [
                Path.home() / "AppData" / "Local" / "Temp",
                Path("C:\\Windows\\Temp"),
            ]
        elif system == "linux":
            log_dirs = [
                Path("/var/log"),
                Path.home() / ".cache",
            ]
        else:
            log_dirs = [
                Path.home() / "Library" / "Logs",
                Path("/var/log"),
            ]
        for log_dir in log_dirs:
            if log_dir.exists():
                for f in log_dir.glob("*.log") if log_dir.exists() else []:
                    if f.stat().st_size < 10 * 1024 * 1024:
                        try:
                            content = f.read_text(encoding="utf-8", errors="replace")
                            dest = self.output_dir / f"app_{f.name}"
                            dest.write_text(content[:500000], encoding="utf-8")
                            results.append({"name": f.name, "file": str(dest), "size": dest.stat().st_size})
                        except Exception:
                            pass
        return results

    def create_log_summary(self, all_results: list[dict]) -> Path:
        summary_path = self.output_dir / "log_summary.txt"
        lines = [
            f"Log Collection Summary",
            f"Generated: {datetime.now().isoformat()}",
            f"Total logs collected: {len(all_results)}",
            f"Total size: {sum(r.get('size', 0) for r in all_results)} bytes",
            f"",
            f"Collected logs:",
        ]
        for r in all_results:
            lines.append(f"  {r.get('name', 'unknown')}: {r.get('file', '')} ({r.get('size', 0)} bytes)")
        summary_path.write_text("\n".join(lines), encoding="utf-8")
        return summary_path
