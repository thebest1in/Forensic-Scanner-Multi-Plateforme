import subprocess
import platform
from pathlib import Path


class MemoryCollector:
    """Memory acquisition and analysis collector."""

    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _run_cmd(self, cmd: str, timeout: int = 60) -> tuple[bool, str]:
        try:
            r = subprocess.run(
                cmd, shell=True, capture_output=True, text=True,
                timeout=timeout, encoding="utf-8", errors="replace",
            )
            return r.returncode == 0, r.stdout.strip() or r.stderr.strip()
        except Exception as e:
            return False, str(e)

    def collect_process_memory(self) -> list[dict]:
        results = []
        system = platform.system().lower()
        if system == "windows":
            cmd = "tasklist /v /fo csv"
        elif system == "linux":
            cmd = "ps auxww"
        else:
            cmd = "ps aux"
        ok, data = self._run_cmd(cmd)
        fpath = self.output_dir / "process_memory_info.txt"
        fpath.write_text(data if ok and data else "[NO DATA]", encoding="utf-8")
        results.append({"name": "process_memory", "file": str(fpath), "size": fpath.stat().st_size})
        return results

    def collect_memory_maps(self) -> list[dict]:
        results = []
        system = platform.system().lower()
        if system == "linux":
            ok, data = self._run_cmd("cat /proc/self/maps 2>/dev/null | head -5000")
            fpath = self.output_dir / "memory_maps.txt"
            fpath.write_text(data if ok and data else "[NOT AVAILABLE]", encoding="utf-8")
            results.append({"name": "memory_maps", "file": str(fpath), "size": fpath.stat().st_size})
        return results

    def collect_swap_info(self) -> list[dict]:
        results = []
        system = platform.system().lower()
        if system == "linux":
            ok, data = self._run_cmd("swapon --show 2>/dev/null; cat /proc/swaps 2>/dev/null")
        elif system == "windows":
            ok, data = self._run_cmd("wmic pagefile list /format:list")
        else:
            ok, data = self._run_cmd("sysctl vm.swapusage 2>/dev/null")
        fpath = self.output_dir / "swap_info.txt"
        fpath.write_text(data if ok and data else "[NOT AVAILABLE]", encoding="utf-8")
        results.append({"name": "swap_info", "file": str(fpath), "size": fpath.stat().st_size})
        return results
