"""Network forensics — port analysis, C2 detection, DNS hijacking."""

SUSPICIOUS_PORTS = {
    "27042": "frida_default",
    "27043": "frida_auxiliary",
    "4444": "default_debug",
    "5555": "android_debug",
    "8080": "proxy_common",
    "9090": "proxy_alt",
    "3128": "squid_proxy",
    "1080": "socks_proxy",
}


def check_network_connections(content: str, source_file: str) -> list[dict]:
    """Parse netstat output for suspicious listening ports and connections."""
    findings = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("Active") or line.startswith("Proto"):
            continue
        parts = line.split()
        if len(parts) < 4:
            continue
        local_addr = parts[3] if len(parts) > 3 else ""
        if ":" in local_addr:
            port = local_addr.rsplit(":", 1)[-1]
            if port in SUSPICIOUS_PORTS:
                reason = SUSPICIOUS_PORTS[port]
                findings.append({
                    "type": "SUSPICIOUS_PORT",
                    "severity": "HIGH" if reason.startswith("frida") else "MEDIUM",
                    "port": port,
                    "reason": reason,
                    "evidence": f"Suspicious port {port} ({reason}) in: {line}",
                    "file": source_file,
                })

    return findings


def check_dns_configuration(content: str, source_file: str) -> list[dict]:
    """Parse DNS configuration for hijacking indicators."""
    findings = []
    dns_servers = []
    for line in content.splitlines():
        line = line.strip()
        if "=" in line:
            val = line.split("=", 1)[-1].strip()
            if val and val != "0.0.0.0" and "." in val:
                dns_servers.append(val)

    suspicious_dns = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1"}
    for dns in dns_servers:
        if dns not in suspicious_dns:
            findings.append({
                "type": "CUSTOM_DNS",
                "severity": "INFO",
                "dns_server": dns,
                "evidence": f"Custom DNS server configured: {dns}",
                "file": source_file,
            })

    if not dns_servers:
        findings.append({
            "type": "DNS_CONFIG",
            "severity": "INFO",
            "evidence": "No DNS servers found in configuration",
            "file": source_file,
        })

    return findings
