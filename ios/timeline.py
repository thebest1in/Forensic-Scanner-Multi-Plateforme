"""iOS forensic timeline builder.

Aggregates timestamps from backup records, parsed databases, and log files
into a unified chronological timeline.
"""
from __future__ import annotations

import csv
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core import logger


def build_ios_timeline(
    backup_dir: Path,
    parsed_data: dict[str, Any],
    output_dir: Path,
) -> Path:
    """Build a unified iOS forensic timeline.

    Args:
        backup_dir: Path to the iOS backup directory
        parsed_data: Aggregated parsed data from iOS parsers
        output_dir: Directory to write the timeline CSV

    Returns:
        Path to the timeline CSV file
    """
    events = []

    # Add backup metadata events
    _collect_backup_events(backup_dir, events)

    # Add SMS events
    if "sms" in parsed_data:
        _collect_sms_events(parsed_data["sms"], events)

    # Add call history events
    if "calls" in parsed_data:
        _collect_call_events(parsed_data["calls"], events)

    # Add Safari history events
    if "safari" in parsed_data:
        _collect_safari_events(parsed_data["safari"], events)

    # Add Wi-Fi connection events
    if "wifi" in parsed_data:
        _collect_wifi_events(parsed_data["wifi"], events)

    # Add application events
    if "applications" in parsed_data:
        _collect_app_events(parsed_data["applications"], events)

    # Sort by timestamp
    events.sort(key=lambda e: e.get("timestamp", ""))

    # Write CSV
    output_dir.mkdir(parents=True, exist_ok=True)
    timeline_path = output_dir / "ios_forensic_timeline.csv"

    with timeline_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f, fieldnames=["timestamp", "source", "event_type", "description", "severity", "artifact"]
        )
        writer.writeheader()
        writer.writerows(events)

    logger.info(f"iOS timeline: {len(events)} events -> {timeline_path.name}")
    return timeline_path


def _collect_backup_events(backup_dir: Path, events: list[dict]):
    """Add backup metadata events."""
    from ios.backup import parse_info_plist, parse_status_plist

    info = parse_info_plist(backup_dir)
    status = parse_status_plist(backup_dir)

    backup_date = info.get("LastBackupDate", "")
    if backup_date:
        events.append({
            "timestamp": backup_date,
            "source": "backup_metadata",
            "event_type": "BACKUP_CREATED",
            "description": f"iOS backup created for {info.get('DeviceName', 'Unknown')}",
            "severity": "INFO",
            "artifact": "Info.plist",
        })


def _collect_sms_events(sms_data: dict, events: list[dict]):
    """Add SMS/iMessage events."""
    messages = sms_data.get("messages", [])
    for msg in messages:
        events.append({
            "timestamp": msg.get("date", ""),
            "source": "sms",
            "event_type": "SMS_MESSAGE",
            "description": f"{msg.get('direction', '?')}: {msg.get('text', '')[:80]}",
            "severity": "INFO",
            "artifact": "sms.db",
        })


def _collect_call_events(call_data: dict, events: list[dict]):
    """Add call history events."""
    calls = call_data.get("calls", [])
    for call in calls:
        events.append({
            "timestamp": call.get("date", ""),
            "source": "call_history",
            "event_type": "CALL",
            "description": f"{call.get('direction', '?')} call to/from {call.get('number', 'Unknown')} ({call.get('duration', 0)}s)",
            "severity": "INFO",
            "artifact": "call_history.db",
        })


def _collect_safari_events(safari_data: dict, events: list[dict]):
    """Add Safari browsing events."""
    visits = safari_data.get("visits", [])
    for visit in visits:
        events.append({
            "timestamp": visit.get("date", ""),
            "source": "safari",
            "event_type": "WEB_VISIT",
            "description": visit.get("url", "")[:100],
            "severity": "INFO",
            "artifact": "History.db",
        })


def _collect_wifi_events(wifi_data: dict, events: list[dict]):
    """Add Wi-Fi connection events."""
    networks = wifi_data.get("networks", [])
    for network in networks:
        events.append({
            "timestamp": network.get("last_connected", ""),
            "source": "wifi",
            "event_type": "WIFI_CONNECT",
            "description": f"Connected to {network.get('ssid', 'Unknown')}",
            "severity": "INFO",
            "artifact": "com.apple.wifi.plist",
        })


def _collect_app_events(app_data: dict, events: list[dict]):
    """Add application installation events."""
    apps = app_data.get("apps", [])
    for app in apps:
        if app.get("suspicious"):
            events.append({
                "timestamp": "",
                "source": "applications",
                "event_type": "SUSPICIOUS_APP",
                "description": f"Flagged app: {app.get('bundle_id', 'Unknown')}",
                "severity": "HIGH",
                "artifact": "Manifest.db",
            })


def compute_event_statistics(events: list[dict]) -> dict[str, Any]:
    """Compute statistics from a list of timeline events."""
    stats = {
        "total_events": len(events),
        "sources": {},
        "event_types": {},
        "severity_counts": {},
        "time_range": {},
    }
    for event in events:
        src = event.get("source", "unknown")
        stats["sources"][src] = stats["sources"].get(src, 0) + 1
        etype = event.get("event_type", "unknown")
        stats["event_types"][etype] = stats["event_types"].get(etype, 0) + 1
        sev = event.get("severity", "INFO")
        stats["severity_counts"][sev] = stats["severity_counts"].get(sev, 0) + 1

    timestamps = [e["timestamp"] for e in events if e.get("timestamp")]
    if timestamps:
        timestamps.sort()
        stats["time_range"] = {
            "earliest": timestamps[0],
            "latest": timestamps[-1],
        }
    return stats
