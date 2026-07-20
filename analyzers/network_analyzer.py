import re
import ipaddress
from pathlib import Path


class NetworkAnalyzer:
    """Network artifact analysis for C2 detection and suspicious connections."""

    C2_INDICATORS = [
        r"(?:\d{1,3}\.){3}\d{1,3}:\d{2,5}",
        r"(?:https?://)?[\w.-]+\.(?:top|xyz|tk|ml|ga|cf|gq|buzz|club|work|icu|cam)\b",
        r"(?:tor|onion)\b",
    ]

    PRIVATE_RANGES = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("127.0.0.0/8"),
    ]

    def __init__(self):
        self._ip_regex = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
        self._url_regex = re.compile(r"https?://[^\s\"'<>]+")
        self._domain_regex = re.compile(r"\b[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.(?:com|net|org|io|info|biz|xyz|top|tk|ml|ga|cf|gq)\b")

    def is_private_ip(self, ip_str: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip_str)
            return any(addr in net for net in self.PRIVATE_RANGES)
        except ValueError:
            return True

    def extract_ips(self, text: str) -> list[str]:
        all_ips = self._ip_regex.findall(text)
        return sorted(set(ip for ip in all_ips if not self.is_private_ip(ip)))

    def extract_urls(self, text: str) -> list[str]:
        return sorted(set(self._url_regex.findall(text)))

    def extract_domains(self, text: str) -> list[str]:
        return sorted(set(self._domain_regex.findall(text)))

    def check_c2_indicators(self, text: str) -> list[dict]:
        findings = []
        for pattern in self.C2_INDICATORS:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                findings.append({
                    "type": "c2_indicator",
                    "pattern": pattern,
                    "match": match[:200],
                    "severity": "suspicious",
                })
        return findings

    def analyze_file(self, filepath: Path) -> dict:
        try:
            content = filepath.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return {"file": filepath.name, "error": "Cannot read file"}
        ips = self.extract_ips(content)
        urls = self.extract_urls(content)
        domains = self.extract_domains(content)
        c2 = self.check_c2_indicators(content)
        return {
            "file": filepath.name,
            "external_ips": ips,
            "urls": urls[:50],
            "domains": domains[:50],
            "c2_indicators": c2,
            "suspicious": len(c2) > 0 or len(ips) > 10,
        }

    def analyze_directory(self, directory: Path) -> list[dict]:
        results = []
        for f in directory.rglob("*"):
            if f.is_file() and f.stat().st_size < 10 * 1024 * 1024:
                result = self.analyze_file(f)
                if result.get("external_ips") or result.get("c2_indicators"):
                    results.append(result)
        return results
