from collections.abc import Sequence
from pathlib import Path
from typing import Any

AGGREGATE_ARTIFACT = "android_bugreport_aggregate"

FORENSIC_TOOL_ALLOWLIST = {
    "frida", "hooking_framework", "xposed", "substrate", "magisk", "root",
}

KNOWN_DUAL_USE_PACKAGES = {
    "com.anydesk.anydeskandroid", "com.teamviewer.teamviewer",
    "com.logmein.rescue", "com.splashtop.raclient", "com.realvnc.remote",
    "com.google.android.apps.chromeremotedesktop",
}


def classify_yara_match(
    rule: str,
    meta: dict[str, Any],
    artifact_path: Path,
    evidence: Sequence[dict[str, Any]],
    *,
    forensic_context: bool = False,
) -> dict[str, Any]:
    """Assess whether a raw YARA match is direct evidence or aggregate context."""
    artifact_type = artifact_type_for(artifact_path)
    severity = str(meta.get("severity", "medium")).lower()
    if artifact_type != AGGREGATE_ARTIFACT:
        tags = {str(t).lower() for t in meta.get("tags", [])}

        if forensic_context and tags & FORENSIC_TOOL_ALLOWLIST:
            return {
                "classification": "authorized_forensic_tooling",
                "confidence": 0.1,
                "authoritative": False,
                "reason": "YARA rule matches a known forensic analysis tool; expected during authorized investigation.",
            }

        matched_values = " ".join(
            str(item.get("matched_value_preview", "")) for item in evidence
        ).lower()
        dual_use_hit = any(
            pkg in matched_values for pkg in KNOWN_DUAL_USE_PACKAGES
        )
        if dual_use_hit or (
            forensic_context and "remote_access" in tags and "rat" in tags
        ):
            return {
                "classification": "dual_use_observation",
                "confidence": 0.3,
                "authoritative": False,
                "reason": (
                    "Matched a known commercial remote-access or dual-use "
                    "application; requires user confirmation."
                ),
            }

        confidence = {"critical": 0.95, "high": 0.85, "medium": 0.65}.get(severity, 0.5)
        return {
            "classification": "strong suspicious evidence",
            "confidence": confidence,
            "authoritative": True,
            "reason": "Rule matched a focused artifact rather than an aggregate bugreport.",
        }

    contexts = "\n".join(
        f"{item.get('context_before', '')} {item.get('matched_value_preview', '')} "
        f"{item.get('context_after', '')}"
        for item in evidence
    ).lower()
    identifiers = {str(item.get("string_identifier", "")) for item in evidence}

    if rule == "Disguised_Suspicious_Package":
        installed_markers = ("package [", "package:", "pkg=", "/data/app/")
        if any(marker in contexts for marker in installed_markers):
            return _classification(
                "strong suspicious evidence",
                0.8,
                True,
                "Known suspicious package appears in an installation/package record.",
            )
        return _classification(
            "likely false positive",
            0.05,
            False,
            "Package name occurs only in a reference/watchlist context, not an installation record.",
        )

    if rule == "Suspicious_Network_Patterns":
        return _classification(
            "contextual evidence requiring corroboration",
            0.55,
            False,
            "A non-standard endpoint is network context, but does not independently prove exfiltration.",
        )

    if rule == "Suspicious_Battery_Consumption":
        return _classification(
            "generic diagnostic text",
            0.1,
            False,
            "Battery, service, permission, and persistence terms occur across unrelated bugreport sections.",
        )

    if rule == "Android_Credential_Harvester":
        return _classification(
            "generic diagnostic text",
            0.1,
            False,
            "Android permission inventories and framework method names are not credential theft evidence.",
        )

    if rule == "Android_Data_Exfiltration":
        command_ids = {"$e8", "$e9"}
        if identifiers & command_ids:
            return _classification(
                "contextual evidence requiring corroboration",
                0.55,
                False,
                "Transfer command text exists, but requires process/package and destination corroboration.",
            )
        return _classification(
            "generic diagnostic text",
            0.05,
            False,
            "Generic upload/POST/archive terms are dispersed through normal bugreport diagnostics.",
        )

    if rule == "Android_Root_Detection_Evasion":
        installed_markers = ("package [", "package:", "pkg=", "/data/app/")
        if any(marker in contexts for marker in installed_markers):
            return _classification(
                "contextual evidence requiring corroboration",
                0.65,
                False,
                "Root-related package appears in package context; installed state still needs confirmation.",
            )
        return _classification(
            "likely false positive",
            0.05,
            False,
            "Root strings occur in access-denied logs, path prefixes, or security watchlists.",
        )

    return _classification(
        "contextual evidence requiring corroboration",
        0.35,
        False,
        "Rule is not approved as direct evidence on an aggregate bugreport artifact.",
    )


def artifact_type_for(path: Path) -> str:
    name = path.name.lower()
    if name.startswith("bugreport-") or "bugreport" in name:
        return AGGREGATE_ARTIFACT
    if path.name in {"third_party_apps.txt", "system_apps.txt", "apk_hashes.txt"}:
        return "android_package_inventory"
    if path.suffix.lower() == ".apk":
        return "android_apk"
    if path.suffix.lower() in {".txt", ".log"}:
        return "focused_diagnostic_text"
    return "unknown"


def representative_evidence(
    evidence: Sequence[dict[str, Any]], instances_per_identifier: int = 3
) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    selected: list[dict[str, Any]] = []
    for item in evidence:
        identifier = str(item.get("string_identifier", ""))
        counts[identifier] = counts.get(identifier, 0) + 1
        if counts[identifier] <= instances_per_identifier:
            selected.append(dict(item))
    total_counts: dict[str, int] = {}
    for item in evidence:
        identifier = str(item.get("string_identifier", ""))
        total_counts[identifier] = total_counts.get(identifier, 0) + 1
    for item in selected:
        item["identifier_occurrence_count"] = total_counts[str(item["string_identifier"])]
    return selected


def _classification(label: str, confidence: float, authoritative: bool, reason: str) -> dict[str, Any]:
    return {
        "classification": label,
        "confidence": confidence,
        "authoritative": authoritative,
        "reason": reason,
    }
