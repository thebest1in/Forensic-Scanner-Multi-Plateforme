from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from ._validation import freeze, json_mapping, parse_datetime, require_text, utc_datetime


@dataclass(frozen=True, slots=True)
class Event:
    event_id: str
    scan_id: str
    artifact_id: str
    timestamp_utc: datetime
    source: str
    event_type: str
    description: str
    package_name: str | None = None
    process_name: str | None = None
    user_identifier: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for name in ("event_id", "scan_id", "artifact_id", "source", "event_type", "description"):
            object.__setattr__(self, name, require_text(getattr(self, name), name))
        object.__setattr__(self, "timestamp_utc", utc_datetime(self.timestamp_utc, "timestamp_utc"))
        object.__setattr__(self, "metadata", freeze(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        return json_mapping({name: getattr(self, name) for name in self.__dataclass_fields__})

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Event":
        values = dict(data)
        values["timestamp_utc"] = parse_datetime(values["timestamp_utc"], "timestamp_utc")
        return cls(**values)
