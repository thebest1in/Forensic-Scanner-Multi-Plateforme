"""APK hash analysis — compare extracted SHA-256 against known databases."""

import json
from pathlib import Path

KNOWN_HASHES_PATH = Path(__file__).resolve().parent.parent / "rules" / "known_apk_hashes.json"


def _load_known_hashes() -> dict:
    """Load known APK hash database."""
    if not KNOWN_HASHES_PATH.exists():
        return {"known_good": {}, "known_bad": {}}
    try:
        return json.loads(KNOWN_HASHES_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {"known_good": {}, "known_bad": {}}


def check_apk_hashes(content: str, source_file: str) -> list[dict]:
    """Parse apk_hashes.txt output and compare against known databases."""
    findings = []
    db = _load_known_hashes()
    known_good = db.get("known_good", {})
    known_bad = db.get("known_bad", {})
    hashes_found = []

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("[") or "EXTRACTION FAILED" in line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        sha256 = parts[0]
        apk_path = parts[1] if len(parts) > 1 else ""
        pkg_name = parts[2] if len(parts) > 2 else ""

        hashes_found.append({
            "hash": sha256,
            "path": apk_path,
            "package": pkg_name,
        })

        if sha256 in known_bad:
            findings.append({
                "type": "KNOWN_MALICIOUS_APK",
                "severity": "CRITICAL",
                "package": pkg_name,
                "hash": sha256,
                "threat": known_bad[sha256].get("threat", "unknown"),
                "evidence": f"Known malicious APK detected: {pkg_name} ({sha256[:16]}...)",
                "file": source_file,
            })
        elif sha256 not in known_good:
            findings.append({
                "type": "UNKNOWN_APK",
                "severity": "MEDIUM",
                "package": pkg_name,
                "hash": sha256,
                "evidence": f"APK not in known-good database: {pkg_name} ({sha256[:16]}...)",
                "file": source_file,
            })

    if hashes_found:
        findings.append({
            "type": "APK_HASH_SUMMARY",
            "severity": "INFO",
            "total": len(hashes_found),
            "known_good": sum(1 for h in hashes_found if h["hash"] in known_good),
            "known_bad": sum(1 for h in hashes_found if h["hash"] in known_bad),
            "unknown": sum(1 for h in hashes_found if h["hash"] not in known_good and h["hash"] not in known_bad),
            "evidence": f"Analyzed {len(hashes_found)} APK hashes",
            "file": source_file,
        })

    return findings
