import time
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable


class ScanStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class ScanResult:
    scanner_name: str
    platform: str
    status: ScanStatus = ScanStatus.PENDING
    start_time: float = 0.0
    end_time: float = 0.0
    artifacts_found: list[dict] = field(default_factory=list)
    threats_detected: list[dict] = field(default_factory=list)
    iocs_matched: list[dict] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    raw_data: dict = field(default_factory=dict)

    @property
    def duration(self) -> float:
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        return 0.0

    @property
    def threat_count(self) -> int:
        return len(self.threats_detected)

    @property
    def artifact_count(self) -> int:
        return len(self.artifacts_found)

    def to_dict(self) -> dict:
        return {
            "scanner_name": self.scanner_name,
            "platform": self.platform,
            "status": self.status.value,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration": self.duration,
            "artifacts_found": self.artifacts_found,
            "threats_detected": self.threats_detected,
            "iocs_matched": self.iocs_matched,
            "metadata": self.metadata,
            "errors": self.errors,
            "artifact_count": self.artifact_count,
            "threat_count": self.threat_count,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)


class BaseScanner(ABC):
    """Base class for all forensic scanners."""

    def __init__(self, name: str, platform: str):
        self.name = name
        self.platform = platform
        self._result: ScanResult | None = None
        self._progress_callback: Callable[[float, str], None] | None = None

    @property
    def result(self) -> ScanResult | None:
        return self._result

    def set_progress_callback(self, callback: Callable[[float, str], None]):
        self._progress_callback = callback

    def _report_progress(self, percent: float, message: str):
        if self._progress_callback:
            try:
                self._progress_callback(percent, message)
            except Exception:
                pass

    @abstractmethod
    def collect_artifacts(self, target: str, output_dir: Path) -> list[dict]:
        """Collect forensic artifacts from the target. Returns list of artifact dicts."""
        pass

    @abstractmethod
    def analyze_artifacts(self, artifacts: list[dict], output_dir: Path) -> list[dict]:
        """Analyze collected artifacts for threats. Returns list of threat dicts."""
        pass

    def scan(self, target: str, output_dir: Path) -> ScanResult:
        """Execute the full scan pipeline."""
        self._result = ScanResult(scanner_name=self.name, platform=self.platform)
        self._result.start_time = time.time()
        self._result.status = ScanStatus.RUNNING

        try:
            self._report_progress(0, f"Starting {self.name} scan...")

            artifacts = self.collect_artifacts(target, output_dir)
            self._result.artifacts_found = artifacts
            self._report_progress(50, f"Collected {len(artifacts)} artifacts. Analyzing...")

            threats = self.analyze_artifacts(artifacts, output_dir)
            self._result.threats_detected = threats
            self._report_progress(90, f"Analysis complete. {len(threats)} threats found.")

            self._result.status = ScanStatus.COMPLETED
            self._report_progress(100, f"Scan complete.")

        except Exception as e:
            self._result.status = ScanStatus.FAILED
            self._result.errors.append(str(e))
            self._report_progress(100, f"Scan failed: {e}")

        finally:
            self._result.end_time = time.time()

        return self._result

    def get_capabilities(self) -> list[str]:
        """Return list of capabilities this scanner supports."""
        return []
