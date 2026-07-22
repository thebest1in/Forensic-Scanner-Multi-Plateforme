import dataclasses
import hashlib
import json
import tempfile
import unittest
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

from compat import legacy_analysis_to_scan_result, legacy_extraction_to_artifacts
from domain import (
    Artifact,
    ArtifactCategory,
    Event,
    Finding,
    Platform,
    ScanResult,
    ScanStatus,
    Severity,
    Verdict,
)


class DomainModelTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name).resolve()
        self.evidence = self.root / "evidence.txt"
        self.evidence.write_bytes(b"canonical evidence")
        self.artifact = self._artifact()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _artifact(self, **changes) -> Artifact:
        values = {
            "artifact_id": "artifact-1",
            "scan_id": "scan-1",
            "platform": Platform.ANDROID,
            "category": ArtifactCategory.LOG,
            "source": "system_logs",
            "local_path": self.evidence,
            "original_path": "adb shell logcat -d",
            "acquired_at_utc": datetime(2026, 7, 22, 10, 0, tzinfo=UTC),
            "source_created_at_utc": None,
            "source_modified_at_utc": None,
            "size_bytes": self.evidence.stat().st_size,
            "sha256": hashlib.sha256(self.evidence.read_bytes()).hexdigest(),
            "acquisition_method": "adb_shell",
            "acquisition_command": "adb shell logcat -d",
            "acquisition_exit_code": 0,
            "metadata": {"nested": {"values": [1, 2]}},
        }
        values.update(changes)
        return Artifact(**values)

    def test_artifact_normalizes_aware_timestamp_to_utc(self) -> None:
        local_time = datetime(2026, 7, 22, 12, 0, tzinfo=timezone(timedelta(hours=2)))
        artifact = self._artifact(acquired_at_utc=local_time)
        self.assertEqual(artifact.acquired_at_utc.utcoffset(), timedelta(0))
        self.assertEqual(artifact.acquired_at_utc.hour, 10)

    def test_artifact_rejects_naive_timestamp(self) -> None:
        with self.assertRaisesRegex(ValueError, "timezone-aware"):
            self._artifact(acquired_at_utc=datetime(2026, 7, 22, 10, 0))

    def test_artifact_rejects_invalid_hash_and_relative_path(self) -> None:
        with self.assertRaisesRegex(ValueError, "sha256"):
            self._artifact(sha256="not-a-hash")
        with self.assertRaisesRegex(ValueError, "absolute local path"):
            self._artifact(local_path=Path("relative.txt"))

    def test_models_and_nested_metadata_are_immutable(self) -> None:
        with self.assertRaises(dataclasses.FrozenInstanceError):
            self.artifact.size_bytes = 0
        with self.assertRaises(TypeError):
            self.artifact.metadata["new"] = True
        with self.assertRaises(TypeError):
            self.artifact.metadata["nested"]["new"] = True

    def test_scan_result_json_round_trip(self) -> None:
        finding = Finding(
            finding_id="finding-1",
            scan_id="scan-1",
            artifact_id="artifact-1",
            analyzer="test",
            analyzer_version="1.0",
            rule_id="TEST-1",
            title="Test finding",
            description="Supporting description",
            severity=Severity.HIGH,
            confidence=0.9,
            observed_at_utc=datetime.now(UTC),
            evidence={"line": "example"},
        )
        event = Event(
            event_id="event-1",
            scan_id="scan-1",
            artifact_id="artifact-1",
            timestamp_utc=datetime.now(UTC),
            source="test",
            event_type="test_event",
            description="Example event",
        )
        result = ScanResult(
            scan_id="scan-1",
            status=ScanStatus.COMPLETED,
            verdict=Verdict.SUSPICIOUS,
            risk_score=55,
            artifacts=(self.artifact,),
            findings=(finding,),
            events=(event,),
            started_at_utc=datetime.now(UTC),
        )
        payload = result.to_json()
        decoded = json.loads(payload)
        self.assertEqual(decoded["schema_version"], "7.0.0")
        self.assertEqual(ScanResult.from_json(payload).to_dict(), result.to_dict())

    def test_scan_result_rejects_orphan_finding(self) -> None:
        finding = Finding(
            finding_id="finding-orphan",
            scan_id="scan-1",
            artifact_id="missing",
            analyzer="test",
            analyzer_version="1.0",
            rule_id="TEST-2",
            title="Orphan",
            description="",
            severity=Severity.INFO,
            confidence=0.5,
            observed_at_utc=datetime.now(UTC),
            evidence={},
        )
        with self.assertRaisesRegex(ValueError, "valid scan artifact"):
            ScanResult(
                scan_id="scan-1",
                status=ScanStatus.COMPLETED,
                verdict=Verdict.CLEAN,
                risk_score=0,
                artifacts=(self.artifact,),
                findings=(finding,),
            )


class CompatibilityConverterTests(unittest.TestCase):
    def test_legacy_extraction_hashes_local_file_and_records_limitations(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "device_info.txt"
            path.write_text("device", encoding="utf-8")
            artifacts = legacy_extraction_to_artifacts(
                {"device_info": path},
                scan_id="scan-compat",
                manifest_metadata=[{"id": "device_info", "adb_cmd": "shell getprop"}],
            )
            artifact = artifacts[0]
            self.assertEqual(artifact.sha256, hashlib.sha256(b"device").hexdigest())
            self.assertEqual(artifact.acquisition_command, "shell getprop")
            self.assertIsNone(artifact.acquisition_exit_code)
            self.assertTrue(artifact.metadata["provenance_limitations"])

    def test_legacy_failure_placeholder_is_not_original_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "failed.txt"
            path.write_text("[EXTRACTION FAILED] no data", encoding="utf-8")
            artifact = legacy_extraction_to_artifacts({"failed": path}, scan_id="scan-failed")[0]
            self.assertFalse(artifact.is_original)
            self.assertTrue(artifact.metadata["legacy_failure_placeholder"])

    def test_legacy_analysis_converter_binds_yara_finding(self) -> None:
        class LegacyResult:
            verdict = "CRITICAL"
            composite_risk_score = 80
            matched_rules = [{"rule": "Example", "file": "artifact.txt", "tags": ["critical"]}]

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "artifact.txt"
            path.write_text("evidence", encoding="utf-8")
            artifacts = legacy_extraction_to_artifacts({"log": path}, scan_id="scan-legacy")
            result = legacy_analysis_to_scan_result(LegacyResult(), scan_id="scan-legacy", artifacts=artifacts)
            self.assertEqual(result.verdict, Verdict.CRITICAL)
            self.assertEqual(result.risk_score, 80)
            self.assertEqual(result.findings[0].artifact_id, artifacts[0].artifact_id)


if __name__ == "__main__":
    unittest.main()
