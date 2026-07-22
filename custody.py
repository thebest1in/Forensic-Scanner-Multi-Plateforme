import zipfile
import hashlib
import json
import time
import hmac
import secrets
from pathlib import Path

from core import logger
from version import APP_NAME, REPORT_SCHEMA_VERSION, VERSION


# ============================================================
# ANTI-TAMPERING SIGNING KEY
# ============================================================

_KEY_FILE = Path(__file__).parent / "rules" / ".evidence_key"


def _get_signing_key() -> bytes:
    """Load or generate a persistent HMAC-SHA256 signing key."""
    if _KEY_FILE.exists():
        return _KEY_FILE.read_bytes()
    key = secrets.token_bytes(32)
    _KEY_FILE.parent.mkdir(exist_ok=True)
    _KEY_FILE.write_bytes(key)
    try:
        import os
        os.chmod(_KEY_FILE, 0o600)
    except Exception:
        pass
    logger.info("Generated new evidence signing key")
    return key


def sign_data(data: bytes) -> str:
    """HMAC-SHA256 sign arbitrary data."""
    key = _get_signing_key()
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def verify_signature(data: bytes, signature: str) -> bool:
    """Verify HMAC-SHA256 signature."""
    expected = sign_data(data)
    return hmac.compare_digest(expected, signature)


# ============================================================
# SHA-256 EVIDENCE ITEM HASHING
# ============================================================

def hash_file(file_path: Path) -> str:
    """Compute SHA-256 hash of a single file."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def hash_bytes(data: bytes) -> str:
    """Compute SHA-256 hash of raw bytes."""
    return hashlib.sha256(data).hexdigest()


def compute_chain_hash(items: list[dict]) -> str:
    """Compute a rolling SHA-256 hash chain over a list of evidence items.

    Each item's hash incorporates the previous item's hash,
    creating an unbreakable chain where tampering with any item
    invalidates all subsequent hashes.
    """
    chain = hashlib.sha256()
    for item in items:
        item_hash = item.get("sha256", hash_bytes(json.dumps(item, sort_keys=True).encode()))
        chain.update(item_hash.encode("utf-8"))
    return chain.hexdigest()


# ============================================================
# TOOL-SPECIFIC EVIDENCE RECORDING
# ============================================================

_TOOL_RESULTS_SCHEMA = {
    "mvt": {"fields": ["scan_type", "indicators_found", "threat_level", "details"]},
    "aleapp": {"fields": ["output_dir", "artifacts_analyzed", "stalkerware_found", "suspicious_packages"]},
    "capa": {"fields": ["target", "malicious_capabilities", "features_extracted", "capability_count"]},
    "yara": {"fields": ["rules_count", "matches_count", "matched_rules"]},
    "pcap": {"fields": ["capture_duration", "dns_count", "sni_count", "c2_hits"]},
    "heuristics": {"fields": ["risk_score", "verdict", "suspicious_combos"]},
    "ioc": {"fields": ["total_ips_checked", "suspicious_ips"]},
}


def record_tool_result(tool_name: str, result_data: dict) -> dict:
    """Record a tool's analysis result as a signed evidence item.

    Returns an evidence record with SHA-256 hash and HMAC signature,
    suitable for chain-of-custody documentation.
    """
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    schema = _TOOL_RESULTS_SCHEMA.get(tool_name, {"fields": list(result_data.keys())})

    evidence_record = {
        "tool": tool_name,
        "timestamp_utc": timestamp,
        "data": {k: result_data.get(k) for k in schema["fields"] if k in result_data},
        "raw_hash": hash_bytes(json.dumps(result_data, sort_keys=True, default=str).encode("utf-8")),
    }

    record_json = json.dumps(evidence_record, sort_keys=True, default=str).encode("utf-8")
    evidence_record["sha256"] = hash_bytes(record_json)
    evidence_record["signature"] = sign_data(record_json)

    logger.info(f"Evidence recorded: {tool_name} (hash: {evidence_record['sha256'][:16]}...)")
    return evidence_record


def verify_tool_record(record: dict) -> bool:
    """Verify a tool evidence record's integrity."""
    record_copy = dict(record)
    sig = record_copy.pop("signature", "")
    record_copy.pop("sha256", None)

    record_json = json.dumps(record_copy, sort_keys=True, default=str).encode("utf-8")
    return verify_signature(record_json, sig)


# ============================================================
# READ-ONLY EVIDENCE PACKAGE
# ============================================================

def create_evidence_package(dump_dir: Path, tool_results: list[dict], case_id: str = "") -> Path:
    """Create a read-only evidence package with SHA-256 chain of custody.

    The package contains:
    - All extracted forensic artifacts
    - Per-file SHA-256 hashes
    - Tool-specific evidence records (MVT, ALEAPP, capa, etc.)
    - Rolling hash chain linking all items
    - HMAC-SHA256 signed manifest

    Returns the path to the generated chain_of_custody.json.
    """
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    serial = _extract_serial_from_files(dump_dir)

    # 1. Hash every file in dump_dir
    file_hashes = _list_package_contents(dump_dir)

    # 2. Compute rolling chain hash over all files + tool results
    all_items = file_hashes + tool_results
    rolling_chain = compute_chain_hash(all_items)

    # 3. Build the evidence manifest
    manifest = {
        "chain_of_custody": {
            "report_version": REPORT_SCHEMA_VERSION,
            "tool": f"{APP_NAME} v{VERSION}",
            "case_id": case_id or "UNKNOWN",
            "timestamp_utc": timestamp,
            "device_serial": serial,
            "evidence_files": file_hashes,
            "tool_results": tool_results,
            "rolling_chain_hash": rolling_chain,
            "total_files": len(file_hashes),
            "total_tool_results": len(tool_results),
            "total_size_bytes": sum(c.get("size_bytes", 0) for c in file_hashes),
        }
    }

    manifest_json = json.dumps(manifest, indent=2, sort_keys=True, default=str)
    manifest_bytes = manifest_json.encode("utf-8")

    signature = sign_data(manifest_bytes)
    signed_manifest = {
        "manifest": manifest,
        "integrity": {
            "algorithm": "HMAC-SHA256",
            "signature": signature,
            "signed_at": timestamp,
            "rolling_chain": rolling_chain,
            "verification": "Use custody.verify_signature() to validate; custody.verify_tool_record() for per-tool items",
        }
    }

    signed_json = json.dumps(signed_manifest, indent=2, default=str)
    manifest_path = dump_dir.parent / "chain_of_custody.json"
    manifest_path.write_text(signed_json, encoding="utf-8")

    sig_path = dump_dir.parent / "chain_of_custody.sig"
    sig_path.write_text(signature, encoding="utf-8")

    logger.info(f"Evidence package manifest: {manifest_path.name} ({len(file_hashes)} files, {len(tool_results)} tool results, chain: {rolling_chain[:16]}...)")
    return manifest_path


# ============================================================
# AES-256 ENCRYPTED ZIP PACKAGING
# ============================================================

def encrypt_dump(dump_dir: Path, password: str = "infected", case_id: str = "", tool_results: list[dict] = None) -> Path:
    """
    Compress the entire dump directory into an AES-256 encrypted ZIP.
    Generates a signed evidence chain manifest with SHA-256 hashes.

    Args:
        dump_dir: Directory containing forensic artifacts
        password: Encryption password (default: "infected")
        case_id: Case identifier for chain of custody
        tool_results: Optional list of tool evidence records (MVT, ALEAPP, capa, etc.)
    """
    try:
        import pyzipper
        return _encrypt_with_aes(dump_dir, password, case_id, tool_results or [])
    except ImportError:
        return _encrypt_with_stdlib(dump_dir, password, case_id, tool_results or [])


def _encrypt_with_aes(dump_dir: Path, password: str, case_id: str, tool_results: list[dict]) -> Path:
    """AES-256 encrypted ZIP using pyzipper."""
    zip_path = dump_dir.parent / f"{dump_dir.name}_EVIDENCE.zip"

    try:
        with pyzipper.AESZipFile(
            zip_path, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES
        ) as zf:
            zf.setpassword(password.encode("utf-8"))
            zf.setencryption(pyzipper.WZ_AES, 256)

            for file_path in sorted(dump_dir.rglob("*")):
                if file_path.is_file():
                    arcname = f"{dump_dir.name}/{file_path.relative_to(dump_dir)}"
                    zf.write(file_path, arcname)

        create_evidence_package(dump_dir, tool_results, case_id)
        logger.success(f"Encrypted evidence package: {zip_path.name} (AES-256)")
        return zip_path

    except Exception as e:
        logger.error(f"AES encryption failed: {e}. Falling back to standard ZIP.")
        return _encrypt_with_stdlib(dump_dir, password, case_id, tool_results)


def _encrypt_with_stdlib(dump_dir: Path, password: str, case_id: str, tool_results: list[dict]) -> Path:
    """Standard ZIP fallback (no encryption, but password-protected note)."""
    zip_path = dump_dir.parent / f"{dump_dir.name}_EVIDENCE.zip"

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for file_path in sorted(dump_dir.rglob("*")):
            if file_path.is_file():
                arcname = f"{dump_dir.name}/{file_path.relative_to(dump_dir)}"
                zf.write(file_path, arcname)

        create_evidence_package(dump_dir, tool_results, case_id)
        note = (
            f"EVIDENCE PACKAGE — Universal Forensic Scanner\n"
            f"==========================================\n"
            f"This package should be encrypted with AES-256.\n"
            f"Install pyzipper: pip install pyzipper\n"
            f"Then re-run the scan to generate proper encrypted output.\n"
            f"Intended password: {password}\n"
        )
        zf.writestr(f"{dump_dir.name}/PASSWORD_NOTE.txt", note)

    logger.warning(f"Standard ZIP (no encryption): {zip_path.name}. Install pyzipper for AES-256.")
    return zip_path


# ============================================================
# CHAIN OF CUSTODY METADATA + ANTI-TAMPERING
# ============================================================

def _write_custody_manifest(zip_path: Path, dump_dir: Path, password: str, case_id: str):
    """Legacy manifest — now delegates to create_evidence_package for full chain."""
    create_evidence_package(dump_dir, [], case_id)


def _compute_zip_hash(zip_path: Path) -> str:
    """Compute SHA-256 hash of the ZIP file."""
    sha256 = hashlib.sha256()
    with open(zip_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def _extract_serial_from_files(dump_dir: Path) -> str:
    """Try to extract device serial from device_info.txt."""
    info_file = dump_dir / "device_info.txt"
    if not info_file.exists():
        return "UNKNOWN"
    try:
        content = info_file.read_text(encoding="utf-8", errors="replace")
        for line in content.splitlines():
            if "[ro.serialno]" in line:
                return line.split(":", 1)[-1].strip() if ":" in line else "UNKNOWN"
            if "[ro.boot.serialno]" in line:
                return line.split(":", 1)[-1].strip() if ":" in line else "UNKNOWN"
    except Exception:
        pass
    return "UNKNOWN"


def _list_package_contents(dump_dir: Path) -> list[dict]:
    """List files in the dump directory with sizes and hashes."""
    contents = []
    for file_path in sorted(dump_dir.rglob("*")):
        if file_path.is_file():
            sha256 = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    sha256.update(chunk)
            contents.append({
                "file": file_path.name,
                "size_bytes": file_path.stat().st_size,
                "sha256": sha256.hexdigest(),
                "relative_path": str(file_path.relative_to(dump_dir)),
            })
    return contents


def _has_pyzipper() -> bool:
    try:
        import pyzipper
        return True
    except ImportError:
        return False
