from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from ._validation import absolute_path, freeze, json_mapping, parse_datetime, require_text, utc_datetime
from .enums import AcquisitionProfile, Platform


@dataclass(frozen=True, slots=True)
class ScanContext:
    scan_id: str
    started_at_utc: datetime
    platform: Platform
    profile: AcquisitionProfile
    operator: str
    workspace_path: Path
    evidence_path: Path
    output_path: Path
    options: Mapping[str, Any] = field(default_factory=dict)
    tool_versions: Mapping[str, str] = field(default_factory=dict)
    target_metadata: Mapping[str, Any] = field(default_factory=dict)
    configuration_snapshot: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "scan_id", require_text(self.scan_id, "scan_id"))
        object.__setattr__(self, "operator", require_text(self.operator, "operator"))
        object.__setattr__(self, "started_at_utc", utc_datetime(self.started_at_utc, "started_at_utc"))
        for name in ("workspace_path", "evidence_path", "output_path"):
            object.__setattr__(self, name, absolute_path(getattr(self, name), name))
        for name in ("options", "tool_versions", "target_metadata", "configuration_snapshot"):
            object.__setattr__(self, name, freeze(getattr(self, name)))

    def to_dict(self) -> dict[str, Any]:
        return json_mapping({name: getattr(self, name) for name in self.__dataclass_fields__})

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ScanContext":
        values = dict(data)
        values["started_at_utc"] = parse_datetime(values["started_at_utc"], "started_at_utc")
        values["platform"] = Platform(values["platform"])
        values["profile"] = AcquisitionProfile(values["profile"])
        for name in ("workspace_path", "evidence_path", "output_path"):
            values[name] = Path(values[name])
        return cls(**values)
