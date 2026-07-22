import queue
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum


class ScanStage(StrEnum):
    INITIALIZING = "initializing"
    INGESTING = "ingesting"
    ANALYZING = "analyzing"
    REMEDIATING = "remediating"
    REPORTING = "reporting"
    TIMELINE = "timeline"
    FINALIZING = "finalizing"
    COMPLETED = "completed"
    COMPLETED_WITH_WARNINGS = "completed_with_warnings"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"


TERMINAL_STAGES = frozenset(
    {
        ScanStage.COMPLETED,
        ScanStage.COMPLETED_WITH_WARNINGS,
        ScanStage.FAILED,
        ScanStage.CANCELLED,
        ScanStage.TIMED_OUT,
    }
)


@dataclass(slots=True)
class ScanLifecycle:
    stage: ScanStage = ScanStage.INITIALIZING
    warnings: list[str] = field(default_factory=list)
    error: str | None = None
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def transition(self, stage: ScanStage, *, warning: str | None = None, error: str | None = None) -> None:
        with self._lock:
            if self.stage in TERMINAL_STAGES:
                raise RuntimeError(f"scan is already terminal: {self.stage.value}")
            if warning:
                self.warnings.append(warning)
            if error:
                self.error = error
            self.stage = stage

    @property
    def is_terminal(self) -> bool:
        with self._lock:
            return self.stage in TERMINAL_STAGES


class StageTimeoutError(TimeoutError):
    def __init__(self, stage: ScanStage, timeout_seconds: float):
        super().__init__(f"{stage.value} exceeded {timeout_seconds:g} seconds")
        self.stage = stage
        self.timeout_seconds = timeout_seconds


def run_with_timeout[T](stage: ScanStage, timeout_seconds: float, operation: Callable[[], T]) -> T:
    """Run one post-analysis operation without letting it block finalization forever.

    A daemon thread is intentional: Python cannot safely kill a running thread.
    On timeout the caller regains control and can finalize the GUI explicitly.
    Operations used here must write to distinct output files.
    """
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")

    outcome: queue.Queue[tuple[bool, object]] = queue.Queue(maxsize=1)

    def target() -> None:
        try:
            outcome.put((True, operation()))
        except BaseException as exc:
            outcome.put((False, exc))

    thread = threading.Thread(target=target, name=f"scan-{stage.value}", daemon=True)
    thread.start()
    try:
        succeeded, value = outcome.get(timeout=timeout_seconds)
    except queue.Empty as exc:
        raise StageTimeoutError(stage, timeout_seconds) from exc
    if not succeeded:
        if isinstance(value, BaseException):
            raise value
        raise RuntimeError(f"{stage.value} returned an invalid failure result")
    return value  # type: ignore[return-value]
