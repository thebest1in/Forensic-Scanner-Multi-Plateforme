"""MITRE ATT&CK mapping — annotate findings with technique IDs."""

import json
from pathlib import Path

MITRE_MAP_PATH = Path(__file__).resolve().parent.parent / "rules" / "mitre_attack_map.json"

_TAG_TO_TECHNIQUE = {
    "frida": "T1620", "hooking_framework": "T1620",
    "xposed": "T1620", "substrate": "T1620",
    "magisk": "T1574", "root": "T1574",
    "remote_access": "T1090", "rat": "T1090",
    "spyware": "T1418", "stalkerware": "T1418",
    "pegasus": "T1418", "zero_click": "T1418",
}


def _load_mitre_map() -> dict:
    if not MITRE_MAP_PATH.exists():
        return {}
    try:
        return json.loads(MITRE_MAP_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}


def map_findings_to_attack(
    forensic_findings: list[dict],
    matched_rules: list[dict],
    heuristic_result: dict | None = None,
) -> list[dict]:
    """Map all findings to MITRE ATT&CK techniques."""
    mappings = []
    seen = set()
    mitre_db = _load_mitre_map()

    for finding in forensic_findings:
        ftype = finding.get("type", "")
        ftype_lower = ftype.lower()
        severity = finding.get("severity", "MEDIUM").upper()
        # Skip low-confidence observations — they are not real threats
        if severity in ("INFO", "LOW") or finding.get("authoritative") is False:
            continue
        entry = mitre_db.get(ftype_lower, {})
        if entry:
            key = (entry["technique"], finding.get("package", finding.get("evidence", "")[:50]))
            if key not in seen:
                seen.add(key)
                mappings.append({
                    "technique": entry["technique"],
                    "tactic": entry["tactic"],
                    "name": entry["name"],
                    "description": entry["description"],
                    "finding_type": ftype,
                    "severity": finding.get("severity", "MEDIUM"),
                    "source": "forensic_analysis",
                    "package": finding.get("package", ""),
                })

    for rule in matched_rules:
        # Skip non-authoritative YARA matches (dual-use, forensic tools)
        if not rule.get("authoritative", True):
            continue
        tags = {t.lower() for t in rule.get("tags", [])}
        rule_name = rule.get("rule", "").lower()
        for tag in tags:
            if tag in _TAG_TO_TECHNIQUE:
                tech_id = _TAG_TO_TECHNIQUE[tag]
                for m_id, m_entry in mitre_db.items():
                    if m_entry.get("technique") == tech_id:
                        key = (tech_id, rule.get("rule", ""))
                        if key not in seen:
                            seen.add(key)
                            mappings.append({
                                "technique": tech_id,
                                "tactic": m_entry["tactic"],
                                "name": m_entry["name"],
                                "description": m_entry["description"],
                                "finding_type": f"yara_{rule.get('rule', 'unknown')}",
                                "severity": rule.get("meta", {}).get("severity", "medium").upper(),
                                "source": "yara_match",
                                "rule": rule.get("rule", ""),
                            })
                        break

    if heuristic_result:
        for pkg_info in heuristic_result.get("flagged_packages", []):
            score = pkg_info.get("score", 0)
            if score >= 30:
                key = ("T1418", pkg_info.get("package", ""))
                if key not in seen:
                    seen.add(key)
                    mappings.append({
                        "technique": "T1418",
                        "tactic": "discovery",
                        "name": "Software Discovery",
                        "description": "High-risk package detected by heuristic analysis",
                        "finding_type": "heuristic_flag",
                        "severity": "HIGH",
                        "source": "heuristic_analysis",
                        "package": pkg_info.get("package", ""),
                    })

    return mappings
