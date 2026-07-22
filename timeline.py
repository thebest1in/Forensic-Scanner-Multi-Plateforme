import re
import csv
from pathlib import Path
from datetime import datetime

from core import logger


# ============================================================
# TIMESTAMP NORMALIZERS — Parse diverse Android log formats
# ============================================================

_PATTERNS = [
    # logcat format: "07-20 12:34:56.789"
    (re.compile(r"(\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3})"), "%m-%d %H:%M:%S.%f"),
    # logcat alternate: "2026-07-20 12:34:56.789"
    (re.compile(r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3})"), "%Y-%m-%d %H:%M:%S.%f"),
    # netstat/ps: "Jul 20 12:34:56"
    (re.compile(r"([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"), "%b %d %H:%M:%S"),
    # dumpsys format: "2026-07-20 12:34:56"
    (re.compile(r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})(?:\s|$)"), "%Y-%m-%d %H:%M:%S"),
    # wifi history: "07/20/2026 12:34:56 PM"
    (re.compile(r"(\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2}\s*[AP]M)"), "%m/%d/%Y %I:%M:%S %p"),
    # ISO with T: "2026-07-20T12:34:56"
    (re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"), "%Y-%m-%dT%H:%M:%S"),
]

# Lines that are pure noise (no timestamp = not timeline-relevant)
_SKIP_EMPTY = re.compile(r"^\s*$|^\[.*EXTRACTION FAILED\]|^---\s*$|^===\s*$")


def _normalize_timestamp(raw: str, year: int | None = None) -> str | None:
    """Try to parse a raw timestamp string into ISO format."""
    raw = raw.strip()
    if not raw:
        return None

    for pattern, fmt in _PATTERNS:
        m = pattern.search(raw)
        if m:
            ts_str = m.group(1)
            try:
                if "%Y" not in fmt:
                    dt = datetime.strptime(ts_str, fmt)
                    if year is None:
                        year = datetime.now().year
                    dt = dt.replace(year=year)
                else:
                    dt = datetime.strptime(ts_str, fmt)
                return dt.strftime("%Y-%m-%d %H:%M:%S")
            except ValueError:
                continue
    return None


# ============================================================
# TIMELINE BUILDERS PER LOG TYPE
# ============================================================

def _extract_events_from_logcat(file_path: Path) -> list[dict]:
    """Parse logcat lines into timeline events."""
    events = []
    year = datetime.now().year
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return events

    for line in content.splitlines():
        if _SKIP_EMPTY.match(line):
            continue
        ts = _normalize_timestamp(line, year)
        if not ts:
            continue
        # Extract tag (usually between PID/TID and message)
        tag_match = re.search(r"\s+(\w[\w./]{2,30})[\s:]", line)
        tag = tag_match.group(1) if tag_match else "logcat"
        events.append({
            "timestamp": ts,
            "source": file_path.name,
            "type": "logcat",
            "tag": tag,
            "detail": line.strip()[:200],
        })
    return events


def _extract_events_from_netstat(file_path: Path) -> list[dict]:
    """Parse netstat output for connection events."""
    events = []
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return events

    for line in content.splitlines():
        if _SKIP_EMPTY.match(line) or "Active" in line or "Proto" in line:
            continue
        # Look for ESTABLISHED or SYN_SENT connections
        if "ESTABLISHED" in line or "SYN_SENT" in line:
            parts = line.split()
            if len(parts) >= 5:
                foreign = parts[4] if "ESTABLISHED" in line else parts[4]
                state = "ESTABLISHED" if "ESTABLISHED" in line else "SYN_SENT"
                events.append({
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "source": file_path.name,
                    "type": "network",
                    "tag": state,
                    "detail": f"{foreign}",
                })
    return events


def _extract_events_from_usb(file_path: Path) -> list[dict]:
    """Parse USB history for connection events."""
    events = []
    year = datetime.now().year
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return events

    for line in content.splitlines():
        if _SKIP_EMPTY.match(line):
            continue
        ts = _normalize_timestamp(line, year)
        if not ts:
            continue
        events.append({
            "timestamp": ts,
            "source": file_path.name,
            "type": "usb",
            "tag": "usb_event",
            "detail": line.strip()[:200],
        })
    return events


def _extract_events_from_wifi(file_path: Path) -> list[dict]:
    """Parse WiFi history for connection events."""
    events = []
    year = datetime.now().year
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return events

    for line in content.splitlines():
        if _SKIP_EMPTY.match(line):
            continue
        ts = _normalize_timestamp(line, year)
        if not ts:
            continue
        events.append({
            "timestamp": ts,
            "source": file_path.name,
            "type": "wifi",
            "tag": "wifi_event",
            "detail": line.strip()[:200],
        })
    return events


def _extract_events_generic(file_path: Path) -> list[dict]:
    """Generic timestamp extraction from any file."""
    events = []
    year = datetime.now().year
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return events

    for line in content.splitlines():
        if _SKIP_EMPTY.match(line):
            continue
        ts = _normalize_timestamp(line, year)
        if ts:
            events.append({
                "timestamp": ts,
                "source": file_path.name,
                "type": "generic",
                "tag": "event",
                "detail": line.strip()[:200],
            })
    return events


# ============================================================
# TIMELINE BUILDER
# ============================================================

_TIMELINE_EXTRACTORS = {
    "system_execution.log": _extract_events_from_logcat,
    "netstat.log": _extract_events_from_netstat,
    "usb_history.txt": _extract_events_from_usb,
    "wifi_history.txt": _extract_events_from_wifi,
}


def build_timeline(
    extracted_files: dict[str, Path],
    dump_dir: Path,
    manifest_metadata: list[dict] | None = None,
) -> Path | None:
    """Build a unified forensic timeline CSV from extracted artifacts."""
    all_events: list[dict] = []

    # Filter to timeline-eligible files from manifest
    timeline_ids = set()
    if manifest_metadata:
        for meta in manifest_metadata:
            if meta.get("timeline", False):
                timeline_ids.add(meta.get("id", ""))

    for file_id, file_path in extracted_files.items():
        if not file_path.exists():
            continue

        # Use specific extractor or generic fallback
        extractor_fn = _TIMELINE_EXTRACTORS.get(file_path.name, _extract_events_generic)
        events = extractor_fn(file_path)
        all_events.extend(events)

    if not all_events:
        logger.info("No timeline events extracted — no timestamps found in logs.")
        return None

    # Sort chronologically
    all_events.sort(key=lambda e: e["timestamp"])

    # Write CSV
    timeline_path = dump_dir / "forensic_timeline.csv"
    with open(timeline_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["timestamp", "source", "type", "tag", "detail"])
        writer.writeheader()
        writer.writerows(all_events)

    logger.success(f"Timeline: {len(all_events)} events -> {timeline_path.name}")
    return timeline_path
