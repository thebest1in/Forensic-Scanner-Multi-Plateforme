import time

import pytest

from scan_lifecycle import ScanLifecycle, ScanStage, StageTimeoutError, run_with_timeout


def test_lifecycle_reaches_explicit_terminal_state() -> None:
    lifecycle = ScanLifecycle()
    lifecycle.transition(ScanStage.INGESTING)
    lifecycle.transition(ScanStage.ANALYZING)
    lifecycle.transition(ScanStage.COMPLETED_WITH_WARNINGS, warning="optional analyzer unavailable")
    assert lifecycle.is_terminal
    assert lifecycle.warnings == ["optional analyzer unavailable"]


def test_terminal_lifecycle_cannot_transition_again() -> None:
    lifecycle = ScanLifecycle()
    lifecycle.transition(ScanStage.COMPLETED)
    with pytest.raises(RuntimeError, match="already terminal"):
        lifecycle.transition(ScanStage.FAILED)


def test_stage_exception_is_retrieved_and_propagated() -> None:
    def fail() -> None:
        raise ValueError("report failed")

    with pytest.raises(ValueError, match="report failed"):
        run_with_timeout(ScanStage.REPORTING, 1, fail)


def test_stage_timeout_returns_control() -> None:
    def slow() -> None:
        time.sleep(0.2)

    started = time.monotonic()
    with pytest.raises(StageTimeoutError, match="timeline exceeded"):
        run_with_timeout(ScanStage.TIMELINE, 0.02, slow)
    assert time.monotonic() - started < 0.15


def test_gui_finalizer_always_posts_terminal_progress_and_restores_controls() -> None:
    from app import ForensicScannerApp

    class FakeApp:
        def __init__(self) -> None:
            self._scan_running = True
            self.progress: list[tuple[float, str]] = []
            self.terminal: list[str] = []
            self.restored = False
            self.rendered = False

        def _update_navigator_status(self, result: object) -> None:
            pass

        def _show_results(self, result: object) -> None:
            self.rendered = True

        def _append_terminal(self, text: str) -> None:
            self.terminal.append(text)

        def _update_progress(self, percent: float, message: str) -> None:
            self.progress.append((percent, message))

        def _restore_quick_buttons(self) -> None:
            self.restored = True

    lifecycle = ScanLifecycle()
    lifecycle.transition(ScanStage.COMPLETED_WITH_WARNINGS, warning="timeline unavailable")
    fake = FakeApp()
    ForensicScannerApp._finalize_scan_ui(fake, object(), lifecycle)

    assert fake.rendered
    assert fake.progress[-1] == (100, "COMPLETED_WITH_WARNINGS")
    assert not fake._scan_running
    assert fake.restored
    assert fake.terminal == ["[WARN] timeline unavailable"]


def test_scaled_analysis_progress_cannot_reset_global_progress_to_80() -> None:
    from app import ForensicScannerApp

    updates: list[tuple[float, str]] = []

    class FakeApp:
        def after(self, delay: int, callback: object, *args: object) -> None:
            callback(*args)

        def _update_progress(self, percent: float, message: str) -> None:
            updates.append((percent, message))

    fake = FakeApp()
    bridge = ForensicScannerApp._scaled_progress_bridge(fake, 20, 70, "Analysis")
    bridge(100, "Analysis complete")
    assert updates == [(70, "Analysis: Analysis complete")]


def test_risk_band_and_authoritative_verdict_escalation_are_explained() -> None:
    from analyzer import AnalysisResult, _explain_verdict

    result = AnalysisResult()
    result.composite_risk_score = 35
    result.composite_risk_level = "LOW_RISK"
    result.verdict = "CRITICAL"
    result.matched_rules = [
        {
            "rule": "Android_Data_Exfiltration",
            "tags": ["data_exfil"],
            "file": "bugreport.txt",
        }
    ]

    reasons = _explain_verdict(result)
    assert reasons[0] == "Weighted score band: LOW_RISK (35/100)."
    assert "escalated to CRITICAL" in reasons[1]
    assert "Android_Data_Exfiltration" in reasons[1]
