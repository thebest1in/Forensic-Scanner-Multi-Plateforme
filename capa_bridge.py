import json
import subprocess
import sys
import shutil
from pathlib import Path
from dataclasses import dataclass, field

from core import logger, BASE_DIR


@dataclass
class CapaResult:
    """Results from Mandiant capa static analysis."""
    available: bool = False
    capabilities: list[dict] = field(default_factory=list)
    malicious_features: list[dict] = field(default_factory=list)
    details: str = ""
    files_analyzed: int = 0

    @property
    def has_findings(self) -> bool:
        return len(self.malicious_features) > 0

    @property
    def severity(self) -> str:
        if not self.available:
            return "UNAVAILABLE"
        if not self.malicious_features:
            return "CLEAN"
        critical_caps = {"keylogger", "screen.capture", "audio.capture", "rootkit",
                         "persistence", "data.exfiltration", "crypto.mining",
                         "reverse.shell", "backdoor"}
        for feat in self.malicious_features:
            if feat.get("capability", "").lower().replace(".", ".") in critical_caps:
                return "CRITICAL"
            tags = set(feat.get("tags", []))
            if tags & critical_caps:
                return "CRITICAL"
        return "SUSPICIOUS"

    def to_dict(self) -> dict:
        return {
            "available": self.available,
            "capabilities": self.capabilities[:50],
            "malicious_features": self.malicious_features,
            "severity": self.severity,
            "details": self.details,
            "files_analyzed": self.files_analyzed,
        }


def check_capa_available() -> bool:
    """Check if capa is installed."""
    if shutil.which("capa"):
        return True
    try:
        result = subprocess.run(
            [sys.executable, "-m", "capa", "--help"],
            capture_output=True, text=True, timeout=10,
        )
        return result.returncode == 0
    except Exception:
        pass
    return False


MALICIOUS_CAPABILITY_KEYWORDS = {
    "keylogger": ["keystroke", "keyboard", "keylog"],
    "screen.capture": ["screenshot", "screen capture", "screen record"],
    "audio.capture": ["microphone", "audio record", "voice record"],
    "camera.capture": ["camera", "photo capture", "video record"],
    "location.tracking": ["gps", "location", "geolocation", "fused location"],
    "data.exfiltration": ["exfiltrat", "data send", "upload data", "http post"],
    "persistence": ["autostart", "boot complete", "persistence", "service restart"],
    "rootkit": ["rootkit", "hide process", "hide file", "kernel module"],
    "reverse.shell": ["shell", "exec command", "command execution", "runtime exec"],
    "backdoor": ["backdoor", "trojan", "rat"],
    "crypto.mining": ["mining", "cryptonight", "stratum"],
    "privilege.escalation": ["suid", "setuid", "privilege", "su binary"],
    "anti.analysis": ["debugger detect", "emulator detect", "root detect", "hook detect"],
    "network.c2": ["beacon", "callback", "c2", "command and control"],
}


def scan_apk(apk_path: Path, output_dir: Path = None, on_progress=None) -> CapaResult:
    """Run capa static analysis on an APK file.

    Capa identifies:
    - Malicious capabilities (keylogger, screen capture, audio recording)
    - Anti-analysis techniques (debugger detection, root detection)
    - Network communication patterns (C2, data exfiltration)
    - Persistence mechanisms
    - Privilege escalation methods
    """
    result = CapaResult()

    if not check_capa_available():
        result.details = "capa not installed. Install via: pip install capa"
        logger.warning("capa not available — skipping APK static analysis")
        return result

    result.available = True

    try:
        if output_dir:
            output_dir.mkdir(parents=True, exist_ok=True)
            json_output = output_dir / f"capa_{apk_path.stem}.json"
        else:
            json_output = Path(f"capa_{apk_path.stem}.json")

        cmd = [
            sys.executable, "-m", "capa",
            str(apk_path),
            "--format", "json",
            "--output", str(json_output),
        ]

        if on_progress:
            on_progress(0, f"Running capa analysis on {apk_path.name}...")

        proc = subprocess.run(
            cmd, capture_output=True, text=True,
            encoding="utf-8", errors="replace",
            timeout=120,
        )

        if json_output.exists():
            with open(json_output, "r", encoding="utf-8") as f:
                data = json.load(f)
                result.capabilities = _parse_capa_output(data)
                result.malicious_features = _filter_malicious_capabilities(result.capabilities)
        elif proc.stdout:
            result.capabilities = _parse_capa_text(proc.stdout)
            result.malicious_features = _filter_malicious_capabilities(result.capabilities)

        result.files_analyzed = 1
        result.details = f"capa analysis complete: {len(result.capabilities)} capabilities, {len(result.malicious_features)} suspicious"

        if on_progress:
            on_progress(100, result.details)

    except subprocess.TimeoutExpired:
        result.details = "capa analysis timed out (120s)"
        logger.warning(result.details)
    except Exception as e:
        result.details = f"capa analysis failed: {e}"
        logger.warning(result.details)

    return result


def scan_directory(dump_dir: Path, output_dir: Path = None, on_progress=None) -> CapaResult:
    """Scan all executable files in a directory with capa."""
    result = CapaResult()

    if not check_capa_available():
        result.details = "capa not installed. Install via: pip install capa"
        logger.warning("capa not available — skipping directory scan")
        return result

    result.available = True

    exe_extensions = {".apk", ".so", ".dex", ".jar", ".bin", ".elf"}
    target_files = []

    for f in dump_dir.rglob("*"):
        if f.is_file() and (f.suffix in exe_extensions or f.stat().st_size > 10000):
            target_files.append(f)

    if not target_files:
        result.details = "No executable files found for capa analysis"
        return result

    all_capabilities = []
    all_malicious = []

    for i, fpath in enumerate(target_files):
        if on_progress and i % 5 == 0:
            pct = int((i / len(target_files)) * 100)
            on_progress(pct, f"capa analyzing: {fpath.name}")

        file_result = scan_apk(fpath, output_dir, on_progress=None)
        all_capabilities.extend(file_result.capabilities)
        all_malicious.extend(file_result.malicious_features)

    result.capabilities = all_capabilities
    result.malicious_features = all_malicious
    result.files_analyzed = len(target_files)
    result.details = f"capa directory scan: {len(all_capabilities)} capabilities from {len(target_files)} files"

    if on_progress:
        on_progress(100, result.details)

    return result


def _parse_capa_output(data: dict) -> list[dict]:
    """Parse capa JSON output."""
    capabilities = []
    if isinstance(data, dict):
        for rule_name, rule_data in data.items():
            if isinstance(rule_data, dict):
                caps = {
                    "name": rule_name,
                    "namespace": rule_data.get("namespace", ""),
                    "tags": rule_data.get("tags", []),
                    "meta": rule_data.get("meta", {}),
                }
                capabilities.append(caps)
    return capabilities


def _parse_capa_text(text: str) -> list[dict]:
    """Parse capa text output."""
    capabilities = []
    for line in text.split("\n"):
        line = line.strip()
        if line and not line.startswith("+") and not line.startswith("="):
            if any(kw in line.lower() for kw in MALICIOUS_CAPABILITY_KEYWORDS):
                capabilities.append({
                    "name": line[:200],
                    "tags": [],
                    "meta": {},
                })
    return capabilities


def _filter_malicious_capabilities(capabilities: list[dict]) -> list[dict]:
    """Filter capabilities to find malicious ones."""
    malicious = []

    for cap in capabilities:
        cap_name = cap.get("name", "").lower()
        cap_tags = set(t.lower() for t in cap.get("tags", []))

        for threat_type, keywords in MALICIOUS_CAPABILITY_KEYWORDS.items():
            for kw in keywords:
                if kw in cap_name or kw in " ".join(cap_tags):
                    malicious.append({
                        "capability": threat_type,
                        "matched_rule": cap.get("name", ""),
                        "tags": list(cap_tags),
                        "severity": "CRITICAL" if threat_type in (
                            "keylogger", "rootkit", "reverse.shell", "backdoor",
                            "crypto.mining",
                        ) else "SUSPICIOUS",
                        "source": "capa",
                    })
                    break

    seen = set()
    unique = []
    for m in malicious:
        key = (m["capability"], m["matched_rule"])
        if key not in seen:
            seen.add(key)
            unique.append(m)

    return unique
