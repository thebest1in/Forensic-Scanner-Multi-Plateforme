import subprocess
import hashlib
from pathlib import Path
from datetime import datetime

from core.base_scanner import BaseScanner, ScanResult
from core.scanner_registry import ScannerRegistry


@ScannerRegistry.register
class DiskScanner(BaseScanner):
    """Disk image and file system forensic scanner."""

    def __init__(self, image_path: str = "", profile: str = "deep", **kwargs):
        super().__init__(name="Disk Forensic Scanner", platform="disk")
        self.image_path = image_path
        self.profile = profile

    def _run_cmd(self, cmd: str, timeout: int = 30) -> tuple[bool, str]:
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
        image = target or self.image_path
        if not image or not Path(image).exists():
            fpath = output_dir / "error.txt"
            fpath.write_text("[ERROR] No disk image provided or file not found", encoding="utf-8")
            return [{"id": "error", "file": str(fpath), "desc": "Error", "size": 0}]

        fpath_hash = output_dir / "image_hashes.txt"
        with open(image, "rb") as f:
            data = f.read(65536)
            md5 = hashlib.md5(data).hexdigest()
            sha1 = hashlib.sha1(data).hexdigest()
            sha256 = hashlib.sha256(data).hexdigest()
        fpath_hash.write_text(f"File: {image}\nMD5: {md5}\nSHA1: {sha1}\nSHA256: {sha256}\nSize: {Path(image).stat().st_size} bytes", encoding="utf-8")
        artifacts.append({"id": "image_hashes", "file": str(fpath_hash), "desc": "Image hash verification", "size": fpath_hash.stat().st_size})

        disk_cmds = {
            "partition_info": f"fdisk -l {image} 2>/dev/null || parted {image} print 2>/dev/null",
            "file_system": f"file {image} 2>/dev/null",
            "strings_printable": f"strings {image} 2>/dev/null | head -10000",
            "strings_unicode": f"strings -el {image} 2>/dev/null | head -5000",
            "deleted_files": f"testdisk /cmd {image} 2>/dev/null | head -500 || echo '[testdisk not available]'",
        }
        items = list(disk_cmds.items())
        for i, (key, cmd) in enumerate(items):
            self._report_progress((i / len(items)) * 50, f"Disk: {key}")
            ok, data = self._run_cmd(cmd)
            fpath = output_dir / f"disk_{key}.txt"
            fpath.write_text(data if ok and data else f"[NO DATA] {key}", encoding="utf-8")
            artifacts.append({"id": key, "file": str(fpath), "desc": key.replace("_", " ").title(), "size": fpath.stat().st_size})

        self._report_progress(75, "Extracting strings for IOC matching...")
        strings_path = output_dir / "extracted_strings.txt"
        ok, data = self._run_cmd(f"strings {image} 2>/dev/null")
        if ok and data:
            strings_path.write_text(data, encoding="utf-8")
            artifacts.append({"id": "extracted_strings", "file": str(strings_path), "desc": "Extracted strings", "size": strings_path.stat().st_size})
        return artifacts

    def analyze_artifacts(self, artifacts: list[dict], output_dir: Path) -> list[dict]:
        threats = []
        disk_indicators = ["malware", "ransomware", "trojan", "backdoor", "keylogger", "rootkit"]
        for art in artifacts:
            fpath = Path(art["file"])
            if not fpath.exists():
                continue
            try:
                content = fpath.read_text(encoding="utf-8", errors="replace").lower()
                for ind in disk_indicators:
                    if ind in content:
                        threats.append({
                            "type": "disk_artifact",
                            "indicator": ind,
                            "source": art["id"],
                            "severity": "critical" if ind in ("ransomware", "rootkit") else "suspicious",
                        })
            except Exception:
                continue
        return threats

    def get_capabilities(self) -> list[str]:
        return ["image_analysis", "string_extraction", "hash_verification", "partition_analysis", "deleted_file_recovery"]
