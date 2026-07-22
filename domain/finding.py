from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from ._validation import freeze, json_mapping, parse_datetime, require_text, utc_datetime
from .enums import Severity


@dataclass(frozen=True, slots=True)
class Finding:
    finding_id: str
    scan_id: str
    artifact_id: str
    analyzer: str
    analyzer_version: str
    rule_id: str
    title: str
    description: str
    severity: Severity
    confidence: float
    observed_at_utc: datetime
    evidence: Mapping[str, Any]
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for name in ("finding_id", "scan_id", "artifact_id", "analyzer", "analyzer_version", "rule_id", "title"):
            object.__setattr__(self, name, require_text(getattr(self, name), name))
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0.0 and 1.0")
        object.__setattr__(self, "observed_at_utc", utc_datetime(self.observed_at_utc, "observed_at_utc"))
        object.__setattr__(self, "evidence", freeze(self.evidence))
        object.__setattr__(self, "metadata", freeze(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        return json_mapping({name: getattr(self, name) for name in self.__dataclass_fields__})

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Finding":
        values = dict(data)
        values["severity"] = Severity(values["severity"])
        values["observed_at_utc"] = parse_datetime(values["observed_at_utc"], "observed_at_utc")
        return cls(**values)
