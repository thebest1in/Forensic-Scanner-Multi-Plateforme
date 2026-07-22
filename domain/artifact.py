import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from ._validation import (
    absolute_path,
    freeze,
    json_mapping,
    optional_parse_datetime,
    optional_utc_datetime,
    parse_datetime,
    require_text,
    utc_datetime,
)
from .enums import ArtifactCategory, Platform

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True)
class Artifact:
    artifact_id: str
    scan_id: str
    platform: Platform
    category: ArtifactCategory
    source: str
    local_path: Path
    original_path: str
    acquired_at_utc: datetime
    source_created_at_utc: datetime | None
    source_modified_at_utc: datetime | None
    size_bytes: int
    sha256: str
    acquisition_method: str
    acquisition_command: str
    acquisition_exit_code: int | None
    is_original: bool = True
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "artifact_id", require_text(self.artifact_id, "artifact_id"))
        object.__setattr__(self, "scan_id", require_text(self.scan_id, "scan_id"))
        object.__setattr__(self, "source", require_text(self.source, "source"))
        object.__setattr__(self, "local_path", absolute_path(self.local_path, "local_path"))
        object.__setattr__(self, "original_path", require_text(self.original_path, "original_path"))
        object.__setattr__(self, "acquired_at_utc", utc_datetime(self.acquired_at_utc, "acquired_at_utc"))
        object.__setattr__(
            self, "source_created_at_utc", optional_utc_datetime(self.source_created_at_utc, "source_created_at_utc")
        )
        object.__setattr__(
            self, "source_modified_at_utc", optional_utc_datetime(self.source_modified_at_utc, "source_modified_at_utc")
        )
        object.__setattr__(self, "acquisition_method", require_text(self.acquisition_method, "acquisition_method"))
        normalized_hash = self.sha256.lower()
        if not _SHA256.fullmatch(normalized_hash):
            raise ValueError("sha256 must contain exactly 64 hexadecimal characters")
        object.__setattr__(self, "sha256", normalized_hash)
        if self.size_bytes < 0:
            raise ValueError("size_bytes must be non-negative")
        object.__setattr__(self, "metadata", freeze(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        return json_mapping({name: getattr(self, name) for name in self.__dataclass_fields__})

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Artifact":
        values = dict(data)
        values["platform"] = Platform(values["platform"])
        values["category"] = ArtifactCategory(values["category"])
        values["local_path"] = Path(values["local_path"])
        values["acquired_at_utc"] = parse_datetime(values["acquired_at_utc"], "acquired_at_utc")
        values["source_created_at_utc"] = optional_parse_datetime(
            values.get("source_created_at_utc"), "source_created_at_utc"
        )
        values["source_modified_at_utc"] = optional_parse_datetime(
            values.get("source_modified_at_utc"), "source_modified_at_utc"
        )
        return cls(**values)
