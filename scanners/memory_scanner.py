import subprocess
import struct
import hashlib
from pathlib import Path

from core.base_scanner import BaseScanner, ScanResult
from core.scanner_registry import ScannerRegistry


@ScannerRegistry.register
class MemoryScanner(BaseScanner):
    """Memory forensics scanner for RAM dump analysis."""

    def __init__(self, dump_path: str = "", profile: str = "deep", **kwargs):
        super().__init__(name="Memory Forensic Scanner", platform="memory")
        self.dump_path = dump_path
        self.profile = profile

    def _run_volatility(self, dump: str, plugin: str, output_dir: Path) -> dict:
        try:
            cmd = f"volatility -f {dump} {plugin}"
            r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60, encoding="utf-8", errors="replace")
            fpath = output_dir / f"vol_{plugin.replace(' ', '_')}.txt"
            fpath.write_text(r.stdout or r.stderr or "[NO OUTPUT]", encoding="utf-8")
            return {"plugin": plugin, "file": str(fpath), "success": r.returncode == 0}
        except Exception as e:
            return {"plugin": plugin, "error": str(e), "success": False}

    def collect_artifacts(self, target: str, output_dir: Path) -> list[dict]:
        output_dir.mkdir(parents=True, exist_ok=True)
        artifacts = []
        dump = target or self.dump_path
        if not dump or not Path(dump).exists():
            fpath = output_dir / "error.txt"
            fpath.write_text("[ERROR] No memory dump file provided or file not found", encoding="utf-8")
            return [{"id": "error", "file": str(fpath), "desc": "Error", "size": 0}]

        vol_plugins = [
            "windows.info",
            "windows.pslist",
            "windows.pstree",
            "windows.netscan",
            "windows.filescan",
            "windows.handles",
            "windows.cmdline",
            "windows.dlllist",
            "windows.registry.hivelist",
            "windows.registry.printkey",
            "windows.malfind",
            "windows.psxview",
            "windows.svcscan",
            "linux.pslist",
            "linux.bash",
            "linux.check_syscall",
            "mac.pslist",
        ]
        for i, plugin in enumerate(vol_plugins):
            self._report_progress((i / len(vol_plugins)) * 50, f"Volatility: {plugin}")
            result = self._run_volatility(dump, plugin, output_dir)
            if result.get("success") and result.get("file"):
                fpath = Path(result["file"])
                artifacts.append({"id": f"vol_{plugin}", "file": result["file"], "desc": f"Volatility {plugin}", "size": fpath.stat().st_size if fpath.exists() else 0})

        fpath = output_dir / "memory_hashes.txt"
        with open(dump, "rb") as f:
            data = f.read(8192)
            md5 = hashlib.md5(data).hexdigest()
            sha256 = hashlib.sha256(data).hexdigest()
        fpath.write_text(f"MD5: {md5}\nSHA256: {sha256}\nSize: {Path(dump).stat().st_size} bytes", encoding="utf-8")
        artifacts.append({"id": "memory_hashes", "file": str(fpath), "desc": "Memory dump hashes", "size": fpath.stat().st_size})
        return artifacts

    def analyze_artifacts(self, artifacts: list[dict], output_dir: Path) -> list[dict]:
        threats = []
        memory_indicators = ["inject", "hollow", "malfind", "suspicious", "hidden", "rootkit"]
        for art in artifacts:
            fpath = Path(art["file"])
            if not fpath.exists():
                continue
            try:
                content = fpath.read_text(encoding="utf-8", errors="replace").lower()
                for ind in memory_indicators:
                    if ind in content:
                        threats.append({
                            "type": "memory_anomaly",
                            "indicator": ind,
                            "source": art["id"],
                            "severity": "critical" if ind in ("inject", "hollow", "rootkit") else "suspicious",
                        })
            except Exception:
                continue
        return threats

    def get_capabilities(self) -> list[str]:
        return ["volatility_analysis", "process_enumeration", "network_connections", "malware_detection", "memory_hashes"]
