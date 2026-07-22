from collections.abc import Mapping
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Any


def require_text(value: str, field_name: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError(f"{field_name} must not be empty")
    return value


def utc_datetime(value: datetime, field_name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    return value.astimezone(UTC)


def optional_utc_datetime(value: datetime | None, field_name: str) -> datetime | None:
    return None if value is None else utc_datetime(value, field_name)


def parse_datetime(value: str | datetime, field_name: str) -> datetime:
    if isinstance(value, datetime):
        return utc_datetime(value, field_name)
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return utc_datetime(parsed, field_name)


def optional_parse_datetime(value: str | datetime | None, field_name: str) -> datetime | None:
    return None if value is None else parse_datetime(value, field_name)


def absolute_path(value: str | Path, field_name: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise ValueError(f"{field_name} must be an absolute local path")
    return path


def freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({str(k): freeze(v) for k, v in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(freeze(item) for item in value)
    if isinstance(value, (set, frozenset)):
        return frozenset(freeze(item) for item in value)
    return value


def json_value(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Mapping):
        return {str(k): json_value(v) for k, v in value.items()}
    if isinstance(value, (tuple, list, set, frozenset)):
        return [json_value(item) for item in value]
    return value


def json_mapping(value: Mapping[str, Any]) -> dict[str, Any]:
    converted = json_value(value)
    if not isinstance(converted, dict):
        raise TypeError("expected a JSON object")
    return converted
