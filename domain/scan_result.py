import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, ClassVar

from ._validation import json_value, optional_parse_datetime, optional_utc_datetime, require_text
from .artifact import Artifact
from .enums import ScanStatus, Verdict
from .event import Event
from .finding import Finding


@dataclass(frozen=True, slots=True)
class ScanResult:
    SCHEMA_VERSION: ClassVar[str] = "7.0.0"

    scan_id: str
    status: ScanStatus
    verdict: Verdict
    risk_score: int
    artifacts: tuple[Artifact, ...] = field(default_factory=tuple)
    findings: tuple[Finding, ...] = field(default_factory=tuple)
    events: tuple[Event, ...] = field(default_factory=tuple)
    acquisition_errors: tuple[str, ...] = field(default_factory=tuple)
    analyzer_errors: tuple[str, ...] = field(default_factory=tuple)
    limitations: tuple[str, ...] = field(default_factory=tuple)
    started_at_utc: datetime | None = None
    completed_at_utc: datetime | None = None
    duration_seconds: float = 0.0

    def __post_init__(self) -> None:
        object.__setattr__(self, "scan_id", require_text(self.scan_id, "scan_id"))
        if not 0 <= self.risk_score <= 100:
            raise ValueError("risk_score must be between 0 and 100")
        if self.duration_seconds < 0:
            raise ValueError("duration_seconds must be non-negative")
        object.__setattr__(self, "artifacts", tuple(self.artifacts))
        object.__setattr__(self, "findings", tuple(self.findings))
        object.__setattr__(self, "events", tuple(self.events))
        object.__setattr__(self, "acquisition_errors", tuple(self.acquisition_errors))
        object.__setattr__(self, "analyzer_errors", tuple(self.analyzer_errors))
        object.__setattr__(self, "limitations", tuple(self.limitations))
        object.__setattr__(self, "started_at_utc", optional_utc_datetime(self.started_at_utc, "started_at_utc"))
        object.__setattr__(self, "completed_at_utc", optional_utc_datetime(self.completed_at_utc, "completed_at_utc"))

        artifact_ids = {artifact.artifact_id for artifact in self.artifacts}
        if len(artifact_ids) != len(self.artifacts):
            raise ValueError("artifact_id values must be unique within a scan result")
        for artifact in self.artifacts:
            if artifact.scan_id != self.scan_id:
                raise ValueError(f"artifact {artifact.artifact_id} belongs to a different scan")
        for finding in self.findings:
            if finding.scan_id != self.scan_id or finding.artifact_id not in artifact_ids:
                raise ValueError(f"finding {finding.finding_id} does not reference a valid scan artifact")
        for event in self.events:
            if event.scan_id != self.scan_id or event.artifact_id not in artifact_ids:
                raise ValueError(f"event {event.event_id} does not reference a valid scan artifact")
        if self.started_at_utc and self.completed_at_utc and self.completed_at_utc < self.started_at_utc:
            raise ValueError("completed_at_utc must not precede started_at_utc")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.SCHEMA_VERSION,
            "scan_id": self.scan_id,
            "status": self.status.value,
            "verdict": self.verdict.value,
            "risk_score": self.risk_score,
            "artifacts": [item.to_dict() for item in self.artifacts],
            "findings": [item.to_dict() for item in self.findings],
            "events": [item.to_dict() for item in self.events],
            "acquisition_errors": list(self.acquisition_errors),
            "analyzer_errors": list(self.analyzer_errors),
            "limitations": list(self.limitations),
            "started_at_utc": json_value(self.started_at_utc),
            "completed_at_utc": json_value(self.completed_at_utc),
            "duration_seconds": self.duration_seconds,
        }

    def to_json(self, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False, sort_keys=True)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ScanResult":
        version = data.get("schema_version")
        if version != cls.SCHEMA_VERSION:
            raise ValueError(f"unsupported schema_version: {version!r}")
        return cls(
            scan_id=data["scan_id"],
            status=ScanStatus(data["status"]),
            verdict=Verdict(data["verdict"]),
            risk_score=int(data["risk_score"]),
            artifacts=tuple(Artifact.from_dict(item) for item in _sequence(data, "artifacts")),
            findings=tuple(Finding.from_dict(item) for item in _sequence(data, "findings")),
            events=tuple(Event.from_dict(item) for item in _sequence(data, "events")),
            acquisition_errors=tuple(str(item) for item in _sequence(data, "acquisition_errors")),
            analyzer_errors=tuple(str(item) for item in _sequence(data, "analyzer_errors")),
            limitations=tuple(str(item) for item in _sequence(data, "limitations")),
            started_at_utc=optional_parse_datetime(data.get("started_at_utc"), "started_at_utc"),
            completed_at_utc=optional_parse_datetime(data.get("completed_at_utc"), "completed_at_utc"),
            duration_seconds=float(data.get("duration_seconds", 0.0)),
        )

    @classmethod
    def from_json(cls, payload: str) -> "ScanResult":
        data = json.loads(payload)
        if not isinstance(data, dict):
            raise ValueError("scan result JSON must contain an object")
        return cls.from_dict(data)


def _sequence(data: Mapping[str, Any], key: str) -> Sequence[Any]:
    value = data.get(key, ())
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise ValueError(f"{key} must be an array")
    return value
