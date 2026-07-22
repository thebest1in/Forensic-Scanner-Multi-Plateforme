import time
import threading
from pathlib import Path

from core import logger, KNOWN_IPS_FILE


# ============================================================
# IOC FEED SOURCES — Open-source C2/spyware blocklists
# ============================================================

IOC_FEEDS = [
    {
        "name": "abuse.ch IP Threat Intel",
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
        "type": "ip_list",
        "comment_prefix": "#",
    },
    {
        "name": "C2 IntelFeeds - Known C2 IPs",
        "url": "https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/IPC2s-30day.csv",
        "type": "csv_ip_col",
        "csv_column": 0,
        "comment_prefix": "#",
    },
    {
        "name": "stamparm IPsum (level 3+)",
        "url": "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt",
        "type": "ip_list",
        "comment_prefix": "#",
    },
    {
        "name": "TinyCheck Stalkerware IPs",
        "url": "https://raw.githubusercontent.com/Te-k/tinycheck/master/iocs/ip_addresses.csv",
        "type": "csv_ip_col",
        "csv_column": 0,
        "comment_prefix": "#",
        "label": "tinycheck",
    },
]


def sync_ioc_feeds(
    known_ips_path: Path | None = None,
    on_complete=None,
    timeout: float = 10.0,
) -> dict:
    """
    Fetch live IOC feeds and append new IPs to known_ips.txt.
    Runs synchronously (call from a thread if needed).
    Returns {feed_name: {status, new_ips, total}}.
    """
    try:
        import requests
    except ImportError:
        logger.warning("requests not installed — IOC feed sync skipped")
        return {}

    target = known_ips_path or KNOWN_IPS_FILE
    existing_ips = _load_existing_ips(target)
    results = {}

    for feed in IOC_FEEDS:
        logger.info(f"Fetching IOC feed: {feed['name']}...")
        try:
            resp = requests.get(feed["url"], timeout=timeout, headers={
                "User-Agent": "PocoX6Pro-ForensicScanner/2.1"
            })
            if resp.status_code != 200:
                results[feed["name"]] = {"status": f"HTTP {resp.status_code}", "new_ips": 0}
                continue

            new_ips = _parse_feed(resp.text, feed, existing_ips)
            if new_ips:
                _append_ips(target, new_ips)
                existing_ips.update(new_ips)
                logger.success(f"IOC feed '{feed['name']}': +{len(new_ips)} new IPs")
            else:
                logger.info(f"IOC feed '{feed['name']}': no new IPs")

            results[feed["name"]] = {"status": "ok", "new_ips": len(new_ips)}

        except Exception as e:
            logger.warning(f"IOC feed '{feed['name']}' failed: {e}")
            results[feed["name"]] = {"status": f"error: {e}", "new_ips": 0}

    if on_complete:
        on_complete(results)
    return results


def _load_existing_ips(path: Path) -> set[str]:
    """Load existing IPs from the IOC file."""
    ips = set()
    if not path.exists():
        return ips
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            ips.add(line)
    return ips


def _parse_feed(text: str, feed: dict, existing: set[str]) -> set[str]:
    """Parse a feed response into new IPs."""
    import re
    ip_regex = re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b"
    )

    new_ips = set()
    comment = feed.get("comment_prefix", "#")
    feed_type = feed.get("type", "ip_list")

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(comment):
            continue

        if feed_type == "csv_ip_col":
            col = feed.get("csv_column", 0)
            parts = line.split(",")
            if len(parts) > col:
                line = parts[col].strip()

        for match in ip_regex.finditer(line):
            ip = match.group()
            if ip not in existing:
                new_ips.add(ip)

    return new_ips


def _append_ips(path: Path, ips: set[str]):
    """Append new IPs to the IOC file."""
    with open(path, "a", encoding="utf-8") as f:
        f.write(f"\n# Auto-synced IOC feeds — {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())}\n")
        for ip in sorted(ips):
            f.write(f"{ip}\n")
