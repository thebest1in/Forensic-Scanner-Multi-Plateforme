"""Proxy and VPN detection — traffic interception, HTTP/SOCKS proxy."""


def check_proxy_config(content: str, source_file: str) -> list[dict]:
    """Parse VPN/proxy configuration for traffic interception."""
    findings = []
    props = {}
    for line in content.splitlines():
        line = line.strip()
        if "=" in line:
            key, _, val = line.partition("=")
            key = key.strip()
            val = val.strip()
            if key and val:
                props[key] = val

    http_proxy = props.get("global.http_proxy", "")
    socks_proxy = props.get("global.socks_proxy", "")

    if http_proxy and http_proxy not in ("", "null", "0.0.0.0:0"):
        findings.append({
            "type": "HTTP_PROXY",
            "severity": "HIGH",
            "proxy": http_proxy,
            "evidence": f"HTTP proxy configured: {http_proxy} — traffic may be intercepted",
            "file": source_file,
        })

    if socks_proxy and socks_proxy not in ("", "null", "0.0.0.0:0"):
        findings.append({
            "type": "SOCKS_PROXY",
            "severity": "HIGH",
            "proxy": socks_proxy,
            "evidence": f"SOCKS proxy configured: {socks_proxy} — traffic may be tunneled",
            "file": source_file,
        })

    return findings
