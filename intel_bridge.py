import json
import time
from pathlib import Path
from dataclasses import dataclass, field

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

from core import logger, BASE_DIR


# ============================================================
# THREAT INTELLIGENCE BRIDGE
# ============================================================

_TINYCHECK_GITHUB_URLS = {
    "domains": "https://raw.githubusercontent.com/Te-k/tinycheck/master/iocs/domains.csv",
    "ips": "https://raw.githubusercontent.com/Te-k/tinycheck/master/iocs/ip_addresses.csv",
    "urls": "https://raw.githubusercontent.com/Te-k/tinycheck/master/iocs/urls.csv",
}

_ABUSEIPDB_API = "https://api.abuseipdb.com/api/v2"
_OTX_API = "https://otx.alienvault.com/api/v1"

_INTEL_CACHE_DIR = BASE_DIR / "rules" / "intel_cache"


@dataclass
class IPReputation:
    """Aggregated reputation data for a single IP address."""
    ip: str = ""
    is_malicious: bool = False
    threat_score: int = 0  # 0-100
    source: str = ""
    abuse_confidence: int = 0
    country: str = ""
    isp: str = ""
    total_reports: int = 0
    otx_pulses: list[dict] = field(default_factory=list)
    tinycheck_match: bool = False
    c2_match: bool = False
    tags: list[str] = field(default_factory=list)
    details: str = ""

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "is_malicious": self.is_malicious,
            "threat_score": self.threat_score,
            "source": self.source,
            "abuse_confidence": self.abuse_confidence,
            "country": self.country,
            "isp": self.isp,
            "total_reports": self.total_reports,
            "otx_pulses": self.otx_pulses,
            "tinycheck_match": self.tinycheck_match,
            "c2_match": self.c2_match,
            "tags": self.tags,
            "details": self.details,
        }


class IntelBridge:
    """Real-time threat intelligence using AlienVault OTX, AbuseIPDB, and TinyCheck.

    Features:
    - AlienVault OTX pulse lookup for IP reputation
    - AbuseIPDB abuse confidence scoring
    - TinyCheck stalkerware/spyware domain + IP feeds
    - Local caching to minimize API calls
    """

    def __init__(self, otx_api_key: str = "", abuseipdb_key: str = ""):
        self._otx_key = otx_api_key
        self._abuseipdb_key = abuseipdb_key
        self._cache = {}
        self._tinycheck_domains: set[str] = set()
        self._tinycheck_ips: set[str] = set()
        _INTEL_CACHE_DIR.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def check_available() -> bool:
        """Check if requests library is available for API calls."""
        return REQUESTS_AVAILABLE

    # --------------------------------------------------------
    # TinyCheck Feed Sync
    # --------------------------------------------------------

    def sync_tinycheck_feeds(self) -> dict:
        """Download TinyCheck stalkerware/spyware IOC feeds from GitHub."""
        if not REQUESTS_AVAILABLE:
            return {"status": "requests not installed"}

        results = {"domains": 0, "ips": 0, "errors": []}

        for feed_type, url in _TINYCHECK_GITHUB_URLS.items():
            try:
                resp = requests.get(url, timeout=30)
                if resp.status_code == 200:
                    lines = resp.text.strip().split("\n")
                    count = 0
                    for line in lines:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        parts = line.split(",")
                        if len(parts) >= 1:
                            value = parts[0].strip().strip('"')
                            if feed_type == "domains":
                                self._tinycheck_domains.add(value)
                                count += 1
                            elif feed_type == "ips":
                                self._tinycheck_ips.add(value)
                                count += 1
                    results[feed_type] = count
                    logger.info(f"TinyCheck {feed_type}: {count} IOCs synced")
                else:
                    results["errors"].append(f"{feed_type}: HTTP {resp.status_code}")
            except Exception as e:
                results["errors"].append(f"{feed_type}: {str(e)[:100]}")

        self._save_cache("tinycheck_domains", list(self._tinycheck_domains))
        self._save_cache("tinycheck_ips", list(self._tinycheck_ips))
        return results

    def load_cached_tinycheck(self) -> bool:
        """Load TinyCheck IOCs from local cache."""
        domains = self._load_cache("tinycheck_domains")
        ips = self._load_cache("tinycheck_ips")
        if domains or ips:
            self._tinycheck_domains = set(domains)
            self._tinycheck_ips = set(ips)
            logger.info(f"TinyCheck cache: {len(self._tinycheck_domains)} domains, {len(self._tinycheck_ips)} IPs")
            return True
        return False

    # --------------------------------------------------------
    # AlienVault OTX Lookup
    # --------------------------------------------------------

    def query_otx(self, ip: str) -> IPReputation:
        """Query AlienVault OTX for IP reputation and pulse matches."""
        rep = IPReputation(ip=ip, source="otx")

        if not REQUESTS_AVAILABLE or not self._otx_key:
            rep.details = "OTX not configured (no API key or requests unavailable)"
            return rep

        cache_key = f"otx_{ip}"
        cached = self._load_cache(cache_key)
        if cached:
            rep.__dict__.update(cached)
            return rep

        try:
            headers = {"X-OTX-API-KEY": self._otx_key}
            resp = requests.get(
                f"{_OTX_API}/indicators/IPv4/{ip}/general",
                headers=headers, timeout=15,
            )
            if resp.status_code == 200:
                data = resp.json()
                rep.country = data.get("country_name", "")
                rep.isp = data.get("asn", "")

                pulse_count = data.get("pulse_info", {}).get("count", 0)
                rep.threat_score = min(pulse_count * 10, 100)

                for pulse in data.get("pulse_info", {}).get("pulses", [])[:10]:
                    rep.otx_pulses.append({
                        "name": pulse.get("name", ""),
                        "description": pulse.get("description", "")[:200],
                        "tags": pulse.get("tags", []),
                        "created": pulse.get("created", ""),
                    })

                if pulse_count > 0:
                    rep.is_malicious = True
                    rep.tags.append("otx_pulse_match")

                # Check for C2-related pulses
                c2_keywords = {"c2", "command", "control", "pegasus", "predator", "trojan", "rat"}
                for pulse in rep.otx_pulses:
                    tags_lower = " ".join(pulse.get("tags", [])).lower()
                    name_lower = pulse.get("name", "").lower()
                    if any(kw in tags_lower or kw in name_lower for kw in c2_keywords):
                        rep.c2_match = True
                        rep.tags.append("c2_infrastructure")
                        rep.threat_score = max(rep.threat_score, 80)
                        break

                self._save_cache(cache_key, rep.to_dict())
                logger.info(f"OTX: {ip} -> pulses={pulse_count}, threat={rep.threat_score}")
            elif resp.status_code == 404:
                rep.details = "IP not found in OTX"
            elif resp.status_code == 429:
                rep.details = "OTX rate limited"
            else:
                rep.details = f"OTX error: HTTP {resp.status_code}"
        except Exception as e:
            rep.details = f"OTX query failed: {str(e)[:100]}"
            logger.warning(f"OTX query failed for {ip}: {e}")

        return rep

    # --------------------------------------------------------
    # AbuseIPDB Lookup
    # --------------------------------------------------------

    def query_abuseipdb(self, ip: str) -> IPReputation:
        """Query AbuseIPDB for IP abuse confidence."""
        rep = IPReputation(ip=ip, source="abuseipdb")

        if not REQUESTS_AVAILABLE or not self._abuseipdb_key:
            rep.details = "AbuseIPDB not configured"
            return rep

        cache_key = f"abuse_{ip}"
        cached = self._load_cache(cache_key)
        if cached:
            rep.__dict__.update(cached)
            return rep

        try:
            headers = {"Key": self._abuseipdb_key, "Accept": "application/json"}
            resp = requests.get(
                f"{_ABUSEIPDB_API}/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers=headers, timeout=15,
            )
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                rep.abuse_confidence = data.get("abuseConfidenceScore", 0)
                rep.total_reports = data.get("totalReports", 0)
                rep.country = data.get("countryCode", "")
                rep.isp = data.get("isp", "")
                rep.threat_score = rep.abuse_confidence
                rep.is_malicious = rep.abuse_confidence >= 50

                if rep.is_malicious:
                    rep.tags.append("abuseipdb_flagged")
                if rep.abuse_confidence >= 90:
                    rep.tags.append("high_confidence_abuse")
                    rep.c2_match = True

                self._save_cache(cache_key, rep.to_dict())
                logger.info(f"AbuseIPDB: {ip} -> confidence={rep.abuse_confidence}%, reports={rep.total_reports}")
            else:
                rep.details = f"AbuseIPDB error: HTTP {resp.status_code}"
        except Exception as e:
            rep.details = f"AbuseIPDB query failed: {str(e)[:100]}"

        return rep

    # --------------------------------------------------------
    # Combined IP Lookup
    # --------------------------------------------------------

    def lookup_ip(self, ip: str) -> IPReputation:
        """Run combined lookup across OTX + AbuseIPDB + TinyCheck cache."""
        rep = IPReputation(ip=ip)

        # TinyCheck local cache check
        if ip in self._tinycheck_ips:
            rep.tinycheck_match = True
            rep.is_malicious = True
            rep.threat_score = max(rep.threat_score, 90)
            rep.tags.append("tinycheck_stalkerware")
            rep.source = "tinycheck"
            logger.warning(f"TinyCheck match: {ip} (stalkerware/spyware IOC)")

        # OTX lookup
        otx_rep = self.query_otx(ip)
        if otx_rep.is_malicious:
            rep.is_malicious = True
            rep.otx_pulses = otx_rep.otx_pulses
            rep.c2_match = otx_rep.c2_match or rep.c2_match
            rep.country = otx_rep.country or rep.country
            rep.isp = otx_rep.isp or rep.isp
            rep.threat_score = max(rep.threat_score, otx_rep.threat_score)
            rep.tags.extend(otx_rep.tags)
            rep.source = "otx" if not rep.source else rep.source

        # AbuseIPDB lookup
        abuse_rep = self.query_abuseipdb(ip)
        if abuse_rep.is_malicious:
            rep.is_malicious = True
            rep.abuse_confidence = abuse_rep.abuse_confidence
            rep.total_reports = abuse_rep.total_reports
            rep.country = abuse_rep.country or rep.country
            rep.isp = abuse_rep.isp or rep.isp
            rep.threat_score = max(rep.threat_score, abuse_rep.threat_score)
            rep.tags.extend(abuse_rep.tags)
            rep.source = rep.source or "abuseipdb"

        return rep

    def lookup_ips(self, ips: list[str]) -> list[IPReputation]:
        """Look up multiple IPs with deduplication."""
        seen = set()
        results = []
        for ip in ips:
            if ip not in seen:
                seen.add(ip)
                results.append(self.lookup_ip(ip))
        return results

    # --------------------------------------------------------
    # Cache Management
    # --------------------------------------------------------

    def _save_cache(self, key: str, data):
        try:
            cache_file = _INTEL_CACHE_DIR / f"{key}.json"
            cache_file.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        except Exception:
            pass

    def _load_cache(self, key: str):
        try:
            cache_file = _INTEL_CACHE_DIR / f"{key}.json"
            if cache_file.exists():
                return json.loads(cache_file.read_text(encoding="utf-8"))
        except Exception:
            pass
        return None
