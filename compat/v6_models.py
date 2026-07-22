import hashlib
import uuid
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from domain import (
    Artifact,
    ArtifactCategory,
    Finding,
    Platform,
    ScanResult,
    ScanStatus,
    Severity,
    Verdict,
)

_ARTIFACT_NAMESPACE = uuid.UUID("906c34d2-a197-4c4d-8194-61cffdf7b1d8")
_FINDING_NAMESPACE = uuid.UUID("30711eeb-5fb1-48c6-b704-27737a4c7774")


def legacy_extraction_to_artifacts(
    extracted_files: Mapping[str, str | Path],
    *,
    scan_id: str,
    platform: Platform = Platform.ANDROID,
    acquisition_method: str = "legacy_v6_extractor",
    manifest_metadata: Sequence[Mapping[str, Any]] | None = None,
) -> tuple[Artifact, ...]:
    """Convert v6.2 extraction output without changing or copying its files.

    This compatibility converter hashes the local output at conversion time. It
    does not claim to reconstruct command timings or exit codes that v6.2 did
    not retain. Those limitations are explicit in artifact metadata.
    """
    metadata_by_id = {str(item.get("id")): item for item in manifest_metadata or ()}
    converted: list[Artifact] = []
    acquired_at = datetime.now(UTC)

    for legacy_id, raw_path in extracted_files.items():
        path = Path(raw_path).resolve()
        if not path.is_file():
            raise ValueError(f"legacy artifact is not a local file: {path}")
        manifest = metadata_by_id.get(str(legacy_id), {})
        digest = _sha256(path)
        failed = _is_failure_placeholder(path)
        artifact_id = str(uuid.uuid5(_ARTIFACT_NAMESPACE, f"{scan_id}:{legacy_id}:{digest}"))
        command = str(manifest.get("adb_cmd", ""))
        converted.append(
            Artifact(
                artifact_id=artifact_id,
                scan_id=scan_id,
                platform=platform,
                category=_category_for(str(legacy_id), path),
                source=str(legacy_id),
                local_path=path,
                original_path=str(manifest.get("original_path") or manifest.get("adb_cmd") or legacy_id),
                acquired_at_utc=acquired_at,
                source_created_at_utc=None,
                source_modified_at_utc=None,
                size_bytes=path.stat().st_size,
                sha256=digest,
                acquisition_method=acquisition_method,
                acquisition_command=command,
                acquisition_exit_code=None,
                is_original=not failed,
                metadata={
                    "legacy_artifact_id": str(legacy_id),
                    "legacy_failure_placeholder": failed,
                    "provenance_limitations": [
                        "v6.2 did not retain the command exit code",
                        "v6.2 did not retain per-command UTC start/end times",
                    ],
                    "manifest": dict(manifest),
                },
            )
        )
    return tuple(converted)


def legacy_analysis_to_scan_result(
    legacy_result: Any,
    *,
    scan_id: str,
    artifacts: Sequence[Artifact],
) -> ScanResult:
    """Create a canonical result from the stable subset of v6.2 AnalysisResult."""
    artifact_tuple = tuple(artifacts)
    by_name = {artifact.local_path.name: artifact for artifact in artifact_tuple}
    findings: list[Finding] = []
    limitations = ["Converted from v6.2 AnalysisResult; analyzer timings and structured errors are unavailable."]

    for index, raw in enumerate(getattr(legacy_result, "matched_rules", ())):
        raw = dict(raw)
        artifact = by_name.get(Path(str(raw.get("file", ""))).name)
        if artifact is None:
            limitations.append(f"Skipped unbound legacy YARA match at index {index}.")
            continue
        rule_id = str(raw.get("rule") or f"legacy_yara_{index}")
        finding_id = str(uuid.uuid5(_FINDING_NAMESPACE, f"{scan_id}:{artifact.artifact_id}:{rule_id}:{index}"))
        findings.append(
            Finding(
                finding_id=finding_id,
                scan_id=scan_id,
                artifact_id=artifact.artifact_id,
                analyzer="yara",
                analyzer_version="legacy-v6.2",
                rule_id=rule_id,
                title=rule_id,
                description=str(raw.get("description") or "Legacy YARA rule match"),
                severity=_legacy_severity(raw),
                confidence=1.0,
                observed_at_utc=datetime.now(UTC),
                evidence=raw,
                metadata={"compatibility_source": "AnalysisResult.matched_rules"},
            )
        )

    return ScanResult(
        scan_id=scan_id,
        status=ScanStatus.COMPLETED,
        verdict=_legacy_verdict(getattr(legacy_result, "verdict", "UNKNOWN")),
        risk_score=int(getattr(legacy_result, "composite_risk_score", 0)),
        artifacts=artifact_tuple,
        findings=tuple(findings),
        limitations=tuple(dict.fromkeys(limitations)),
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_failure_placeholder(path: Path) -> bool:
    try:
        return path.read_bytes()[:64].startswith(b"[EXTRACTION FAILED]")
    except OSError:
        return False


def _category_for(legacy_id: str, path: Path) -> ArtifactCategory:
    value = f"{legacy_id} {path.name}".lower()
    if any(token in value for token in ("netstat", "network", "wifi", "vpn", "pcap")):
        return ArtifactCategory.NETWORK
    if any(token in value for token in ("app", "package", "apk")):
        return ArtifactCategory.APPLICATION
    if path.suffix.lower() in {".db", ".sqlite", ".sqlite3"}:
        return ArtifactCategory.DATABASE
    if any(token in value for token in ("log", "process", "battery", "notification")):
        return ArtifactCategory.LOG
    if "device_info" in value:
        return ArtifactCategory.DEVICE_INFO
    return ArtifactCategory.OTHER


def _legacy_verdict(value: str) -> Verdict:
    normalized = str(value).strip().lower()
    return {
        "clean": Verdict.CLEAN,
        "low_risk": Verdict.LOW_RISK,
        "suspicious": Verdict.SUSPICIOUS,
        "critical": Verdict.CRITICAL,
    }.get(normalized, Verdict.UNKNOWN)


def _legacy_severity(raw: Mapping[str, Any]) -> Severity:
    explicit = str(raw.get("severity", "")).lower()
    if explicit in {item.value for item in Severity}:
        return Severity(explicit)
    tags = {str(tag).lower() for tag in raw.get("tags", ())}
    if tags & {"critical", "pegasus", "reverse_shell", "spyware", "stalkerware"}:
        return Severity.CRITICAL
    return Severity.MEDIUM
