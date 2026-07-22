from pathlib import Path
from typing import Any


def collect_match_evidence(
    match: Any,
    artifact_path: Path,
    data: bytes,
    context_bytes: int = 160,
) -> list[dict[str, Any]]:
    """Expand a yara.Match into stable, JSON-safe per-string evidence records."""
    records: list[dict[str, Any]] = []
    for string_match in getattr(match, "strings", ()):
        identifier = getattr(string_match, "identifier", None)
        instances = getattr(string_match, "instances", None)
        if identifier is not None and instances is not None:
            for instance in instances:
                offset = int(instance.offset)
                matched = bytes(instance.matched_data)
                records.append(
                    _record(match, artifact_path, data, identifier, offset, matched, context_bytes)
                )
            continue

        # yara-python before StringMatchInstance used (offset, identifier, data).
        offset, legacy_identifier, matched = string_match
        records.append(
            _record(
                match,
                artifact_path,
                data,
                str(legacy_identifier),
                int(offset),
                bytes(matched),
                context_bytes,
            )
        )
    return records


def _record(
    match: Any,
    artifact_path: Path,
    data: bytes,
    identifier: str,
    offset: int,
    matched: bytes,
    context_bytes: int,
) -> dict[str, Any]:
    start = max(0, offset - context_bytes)
    end = min(len(data), offset + len(matched) + context_bytes)
    return {
        "rule": str(match.rule),
        "namespace": str(getattr(match, "namespace", "default")),
        "tags": list(getattr(match, "tags", ())),
        "severity": str(getattr(match, "meta", {}).get("severity", "unknown")).upper(),
        "artifact_path": str(artifact_path.resolve()),
        "string_identifier": identifier,
        "matched_value_preview": _preview(matched, 160),
        "offset": offset,
        "context_before": _preview(data[start:offset], context_bytes),
        "context_after": _preview(data[offset + len(matched) : end], context_bytes),
        "artifact_type": _artifact_type(artifact_path),
        "confidence": 0.0,
    }


def _preview(value: bytes, limit: int) -> str:
    text = value.decode("utf-8", errors="replace")
    return " ".join(text.replace("\x00", " ").split())[:limit]


def _artifact_type(path: Path) -> str:
    name = path.name.lower()
    if name.startswith("bugreport-") or "bugreport" in name:
        return "android_bugreport_aggregate"
    if path.suffix.lower() in {".log", ".txt"}:
        return "diagnostic_text"
    if path.suffix.lower() == ".apk":
        return "android_apk"
    return "unknown"
