import re
import struct
import socket
import time
from pathlib import Path

from core import logger, run_adb, ADB_TIMEOUT


# ============================================================
# C2 DOMAIN SIGNATURES
# ============================================================

C2_INDICATORS = {
    "ngrok": [".ngrok.io", ".ngrok-free.app"],
    "duckdns": [".duckdns.org"],
    "serveo": [".serveo.net"],
    "tunnel": [".localtunnel.me"],
    "burp": [".burpcollaborator.net"],
    "oast": [".oast.fun", ".oast.pro", ".oast.live"],
    "canary": [".canarytokens.com"],
    "pipedream": [".pipedream.net"],
    "interactsh": [".interact.sh"],
    "c2_known": [
        "commandandcontrol.com", "data-exfil.net",
    ],
}

SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".buzz", ".top", ".xyz", ".club"}

# Whitelist — legitimate infrastructure to exclude from alerts
WHITELIST_DOMAINS = {
    "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com",
    "youtube.com", "ytimg.com", "googlevideo.com",
    "android.com", "googlesyndication.com", "googletagmanager.com",
    "apple.com", "icloud.com", "mzstatic.com",
    "microsoft.com", "windows.com", "office.com", "live.com",
    "amazonaws.com", "cloudfront.net", "amazon.com",
    "facebook.com", "fbcdn.net", "instagram.com",
    "twitter.com", "x.com", "twimg.com",
    "github.com", "githubusercontent.com",
    "akamai.com", "akamaiedge.net", "akamaihd.net",
    "cloudflare.com", "cdnjs.cloudflare.com",
    "xiaomi.com", "miui.com", "mi.com",
    "samsung.com", "samsungcloud.com",
    "whatsapp.com", "whatsapp.net",
    "telegram.org", "t.me",
    "signal.org", "signal-cdn.org",
    "mozilla.org", "firefox.com",
    "opera.com",
}

WHITELIST_IP_PREFIXES = [
    "8.8.", "8.3.", "8.4.",        # Google DNS
    "1.1.", "1.0.",                 # Cloudflare DNS
    "208.67.",                      # OpenDNS
    "9.9.9.",                       # Quad9
]

# Capture duration presets
CAPTURE_PRESETS = {
    "quick": {"duration": 180, "label": "Quick Scan (3 min)", "description": "Detects active data exfiltration"},
    "standard": {"duration": 300, "label": "Standard (5 min)", "description": "Balanced capture window"},
    "extended": {"duration": 900, "label": "Extended (15 min)", "description": "Captures intermittent C2 beaconing"},
    "continuous": {"duration": 3600, "label": "Continuous (1 hour)", "description": "Long-term monitoring for dormant threats"},
}


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def _extract_base_domain(domain: str) -> str:
    """Extract the base domain (e.g., 'example.com' from 'sub.example.com')."""
    parts = domain.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain


def _is_ip_whitelisted(ip: str) -> bool:
    """Check if an IP belongs to a whitelisted DNS provider."""
    for prefix in WHITELIST_IP_PREFIXES:
        if ip.startswith(prefix):
            return True
    return False


def _dns_reverse_lookup(ip: str) -> str:
    """Perform reverse DNS lookup on an IP address."""
    try:
        result = socket.gethostbyaddr(ip)
        return result[0] if result else ""
    except (socket.herror, socket.gaierror, OSError):
        return ""


class PCAPBridge:
    """Live packet capture and DNS/TLS SNI analysis via ADB.

    Features:
    - Configurable capture windows (3 min to 1 hour)
    - IP/domain whitelisting to reduce false positives
    - DNS reverse resolution for IP validation
    - C2 domain detection with contextual scoring
    """

    def __init__(self, serial: str, duration: int = 60, preset: str = None):
        self._serial = serial
        if preset and preset in CAPTURE_PRESETS:
            self._duration = CAPTURE_PRESETS[preset]["duration"]
        else:
            self._duration = duration
        self._dns_queries: list[dict] = []
        self._tls_sni: list[dict] = []
        self._c2_hits: list[dict] = []
        self._suspicious_tld_hits: list[dict] = []
        self._whitelisted_hits: list[dict] = []
        self._dns_cache: dict[str, str] = {}

    @property
    def dns_queries(self) -> list[dict]:
        return self._dns_queries.copy()

    @property
    def tls_sni(self) -> list[dict]:
        return self._tls_sni.copy()

    @property
    def c2_hits(self) -> list[dict]:
        return self._c2_hits.copy()

    def capture(self, on_progress=None) -> dict:
        """
        Run tcpdump on device, pull PCAP, parse DNS + TLS SNI.
        Falls back to DNS-only capture if tcpdump unavailable.
        """
        _report(on_progress, 0, f"Starting packet capture ({self._duration}s)...")

        # Try tcpdump first
        pcap_path = self._try_tcpdump(on_progress)

        if pcap_path and pcap_path.exists():
            _report(on_progress, 70, "Parsing PCAP file...")
            self._parse_pcap(pcap_path)
        else:
            # Fallback: DNS cache dump
            _report(on_progress, 70, "tcpdump unavailable, reading DNS cache...")
            self._read_dns_cache()

        _report(on_progress, 85, "Analyzing traffic for C2 indicators...")
        self._analyze_traffic()

        result = {
            "dns_queries": self._dns_queries,
            "tls_sni": self._tls_sni,
            "c2_hits": self._c2_hits,
            "suspicious_tld_hits": self._suspicious_tld_hits,
            "whitelisted_hits": len(self._whitelisted_hits),
            "total_dns": len(self._dns_queries),
            "total_sni": len(self._tls_sni),
            "capture_duration": self._duration,
        }

        _report(on_progress, 100, f"Capture complete: {len(self._dns_queries)} DNS, {len(self._tls_sni)} SNI")
        return result

    def _try_tcpdump(self, on_progress=None) -> Path | None:
        """Attempt to run tcpdump on device and pull the PCAP."""
        # Clean up old capture
        run_adb(f"-s {self._serial} shell rm -f /data/local/tmp/trace.pcap", timeout=5)

        # Check if tcpdump exists
        success, output = run_adb(
            f"-s {self._serial} shell which tcpdump",
            timeout=5,
        )
        if not success or not output or "not found" in (output or ""):
            logger.warning("tcpdump not available on device")
            return None

        # Run tcpdump
        _report(on_progress, 5, f"Capturing packets for {self._duration}s...")
        cmd = (
            f"-s {self._serial} shell "
            f"tcpdump -i any -w /data/local/tmp/trace.pcap "
            f"-G {self._duration} -W 1 -q"
        )
        success, _ = run_adb(cmd, timeout=self._duration + 15)

        if not success:
            logger.warning("tcpdump capture failed or timed out")
            return None

        # Pull the PCAP
        local_pcap = Path(__file__).parent / "trace.pcap"
        success, _ = run_adb(
            f"-s {self._serial} pull /data/local/tmp/trace.pcap {local_pcap}",
            timeout=30,
        )
        if success and local_pcap.exists():
            size_kb = local_pcap.stat().st_size / 1024
            logger.success(f"PCAP captured: {size_kb:.1f} KB")
            return local_pcap

        return None

    def _read_dns_cache(self):
        """Read DNS cache from dumpsys as fallback."""
        success, output = run_adb(
            f"-s {self._serial} shell dumpsys connectivity",
            timeout=ADB_TIMEOUT,
        )
        if not success or not output:
            return

        # Extract domain names from connectivity dump
        domain_pattern = re.compile(
            r"([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}"
        )
        for match in domain_pattern.finditer(output):
            domain = match.group().lower()
            if len(domain) > 5 and not domain.endswith((".local", ".lan", ".in-addr")):
                self._dns_queries.append({
                    "domain": domain,
                    "source": "dns_cache",
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                })

    def _parse_pcap(self, pcap_path: Path):
        """Parse a PCAP file for DNS queries and TLS SNI."""
        try:
            with open(pcap_path, "rb") as f:
                # Read global header
                header = f.read(24)
                if len(header) < 24:
                    return

                magic = struct.unpack("<I", header[:4])[0]
                if magic == 0xa1b2c3d4:
                    big_endian = False
                elif magic == 0xd4c3b2a1:
                    big_endian = True
                else:
                    logger.warning("Not a valid PCAP file")
                    return

                # Read packets
                packet_count = 0
                while True:
                    pkt_header = f.read(16)
                    if len(pkt_header) < 16:
                        break

                    if big_endian:
                        incl_len = struct.unpack(">I", pkt_header[8:12])[0]
                    else:
                        incl_len = struct.unpack("<I", pkt_header[8:12])[0]

                    pkt_data = f.read(incl_len)
                    if len(pkt_data) < incl_len:
                        break

                    self._parse_packet(pkt_data)
                    packet_count += 1

                    if packet_count > 10000:
                        break

                logger.info(f"PCAP parsed: {packet_count} packets, {len(self._dns_queries)} DNS, {len(self._tls_sni)} SNI")

        except Exception as e:
            logger.error(f"PCAP parse error: {e}")

    def _parse_packet(self, data: bytes):
        """Parse a single packet for DNS and TLS SNI."""
        # Skip Ethernet header (14 bytes)
        if len(data) < 34:
            return

        eth_proto = struct.unpack("!H", data[12:14])[0]
        if eth_proto != 0x0800:  # Not IPv4
            return

        # Parse IP header
        ip_header = data[14:]
        ip_proto = ip_header[9]
        src_ip = socket.inet_ntoa(ip_header[12:16])
        dst_ip = socket.inet_ntoa(ip_header[16:20])

        if ip_proto == 17:  # UDP
            # Parse UDP header
            if len(ip_header) < 20:
                return
            udp_header = ip_header[20:]
            src_port = struct.unpack("!H", udp_header[0:2])[0]
            dst_port = struct.unpack("!H", udp_header[2:4])[0]

            # DNS (port 53)
            if src_port == 53 or dst_port == 53:
                self._parse_dns(udp_header[8:], src_ip)

        elif ip_proto == 6:  # TCP
            # Parse TCP header for TLS SNI
            if len(ip_header) < 20:
                return
            tcp_header = ip_header[20:]
            dst_port = struct.unpack("!H", tcp_header[2:4])[0]

            if dst_port == 443:
                payload = tcp_header[20:]
                self._parse_tls_sni(payload, src_ip, dst_ip)

    def _parse_dns(self, data: bytes, src_ip: str):
        """Parse DNS response for domain names."""
        if len(data) < 12:
            return

        # Skip header, parse question section
        offset = 12
        qdcount = struct.unpack("!H", data[4:6])[0]

        for _ in range(qdcount):
            if offset >= len(data):
                break

            # Parse domain name
            domain = []
            while offset < len(data):
                length = data[offset]
                if length == 0:
                    offset += 1
                    break
                if length >= 192:  # Compression pointer
                    break
                offset += 1
                if offset + length > len(data):
                    break
                label = data[offset:offset + length].decode("ascii", errors="replace")
                domain.append(label)
                offset += length

            if domain:
                domain_str = ".".join(domain).lower()
                if len(domain_str) > 3:
                    self._dns_queries.append({
                        "domain": domain_str,
                        "source": "pcap",
                        "src_ip": src_ip,
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    })

            # Skip type and class
            offset += 4

    def _parse_tls_sni(self, data: bytes, src_ip: str, dst_ip: str):
        """Parse TLS ClientHello for SNI extension."""
        if len(data) < 5:
            return

        # Check for TLS handshake
        if data[0] != 0x16:  # Not a handshake
            return

        # Skip TLS record header, get handshake type
        if len(data) < 9:
            return
        handshake_type = data[5]
        if handshake_type != 0x01:  # Not ClientHello
            return

        # Parse ClientHello for SNI
        try:
            offset = 5 + 3  # handshake header
            # Skip client version (2) and random (32)
            offset += 34

            if offset >= len(data):
                return

            # Session ID
            session_len = data[offset]
            offset += 1 + session_len

            # Cipher suites
            if offset + 2 > len(data):
                return
            cipher_len = struct.unpack("!H", data[offset:offset + 2])[0]
            offset += 2 + cipher_len

            # Compression methods
            if offset >= len(data):
                return
            comp_len = data[offset]
            offset += 1 + comp_len

            # Extensions
            if offset + 2 > len(data):
                return
            ext_len = struct.unpack("!H", data[offset:offset + 2])[0]
            offset += 2

            ext_end = offset + ext_len
            while offset + 4 <= ext_end and offset + 4 <= len(data):
                ext_type = struct.unpack("!H", data[offset:offset + 2])[0]
                ext_size = struct.unpack("!H", data[offset + 2:offset + 4])[0]

                if ext_type == 0x0000:  # SNI extension
                    # Skip server name list length (2) and server name type (1)
                    if offset + 7 + 2 <= len(data):
                        sni_len = struct.unpack("!H", data[offset + 7:offset + 9])[0]
                        if offset + 9 + sni_len <= len(data):
                            sni = data[offset + 9:offset + 9 + sni_len].decode("ascii", errors="replace")
                            if sni:
                                self._tls_sni.append({
                                    "sni": sni.lower(),
                                    "src_ip": src_ip,
                                    "dst_ip": dst_ip,
                                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                                })
                    break

                offset += 4 + ext_size

        except Exception:
            pass

    def _analyze_traffic(self):
        """Cross-reference captured traffic against C2 indicators with whitelisting."""
        all_domains = set()

        for q in self._dns_queries:
            all_domains.add(q["domain"])
        for s in self._tls_sni:
            all_domains.add(s["sni"])

        for domain in all_domains:
            domain_lower = domain.lower()

            # Whitelist check — skip legitimate domains
            base_domain = _extract_base_domain(domain_lower)
            if base_domain in WHITELIST_DOMAINS or domain_lower in WHITELIST_DOMAINS:
                continue

            is_whitelisted = False
            for wl_domain in WHITELIST_DOMAINS:
                if domain_lower.endswith("." + wl_domain):
                    is_whitelisted = True
                    break
            if is_whitelisted:
                self._whitelisted_hits.append({"domain": domain, "reason": "whitelisted"})
                continue

            # Check C2 indicators
            for category, indicators in C2_INDICATORS.items():
                for indicator in indicators:
                    if indicator.lower() in domain_lower:
                        self._c2_hits.append({
                            "domain": domain,
                            "category": category,
                            "indicator": indicator,
                        })
                        logger.warning(f"C2 indicator found: {domain} ({category})")

            # Check suspicious TLDs
            for tld in SUSPICIOUS_TLDS:
                if domain_lower.endswith(tld):
                    self._suspicious_tld_hits.append({
                        "domain": domain,
                        "tld": tld,
                    })
                    logger.warning(f"Suspicious TLD: {domain}")

        # DNS reverse resolution for C2 hits (validate IPs)
        for hit in self._c2_hits:
            for q in self._dns_queries:
                if q["domain"] == hit["domain"]:
                    ip = q.get("src_ip", "")
                    if ip and not _is_ip_whitelisted(ip):
                        hit["source_ip"] = ip
                        hit["reverse_dns"] = _dns_reverse_lookup(ip)

    @staticmethod
    def get_capture_presets() -> dict:
        """Return available capture duration presets."""
        return dict(CAPTURE_PRESETS)


def _report(on_progress, percent, message):
    if on_progress:
        try:
            on_progress(percent, message)
        except Exception:
            pass
