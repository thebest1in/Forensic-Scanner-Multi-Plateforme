from pathlib import Path
from typing import Any

import yara

from analyzer import AnalysisResult, _compute_composite_risk, _compute_verdict, analyze
from yara_context import classify_yara_match


def _evidence(identifier: str, before: str, value: str, after: str) -> dict[str, Any]:
    return {
        "string_identifier": identifier,
        "context_before": before,
        "matched_value_preview": value,
        "context_after": after,
    }


def test_watchlist_package_in_aggregate_bugreport_is_not_installation_evidence(tmp_path: Path) -> None:
    path = tmp_path / "bugreport-device.txt"
    assessment = classify_yara_match(
        "Disguised_Suspicious_Package",
        {"severity": "high"},
        path,
        [_evidence("$pkg2", "parental.control,", "com.mspy.lite", ",family.safety")],
    )
    assert assessment["classification"] == "likely false positive"
    assert not assessment["authoritative"]


def test_package_inventory_match_remains_authoritative(tmp_path: Path) -> None:
    path = tmp_path / "third_party_apps.txt"
    assessment = classify_yara_match(
        "Disguised_Suspicious_Package",
        {"severity": "high"},
        path,
        [_evidence("$pkg2", "package:", "com.mspy.lite", "")],
    )
    assert assessment["classification"] == "strong suspicious evidence"
    assert assessment["authoritative"]


def test_numeric_configuration_value_is_not_a_network_endpoint() -> None:
    rules = yara.compile(filepath=str(Path("rules/poco_rules.yar").resolve()))
    data = b"ESTABLISHED timeout_millis value:9999 _id:2644"
    names = {match.rule for match in rules.match(data=data)}
    assert "Suspicious_Network_Patterns" not in names


def test_real_nonstandard_established_endpoint_still_matches() -> None:
    rules = yara.compile(filepath=str(Path("rules/poco_rules.yar").resolve()))
    data = b"ESTABLISHED tcp 10.0.0.2:51000 203.0.113.9:9999 "
    names = {match.rule for match in rules.match(data=data)}
    assert "Suspicious_Network_Patterns" in names


def test_context_only_yara_does_not_escalate_authoritative_verdict() -> None:
    result = AnalysisResult()
    result.tool_status = {name: "disabled" for name in ("mvt", "apkid", "quark", "capa", "aleapp")}
    result.matched_rules = [
        {
            "rule": "Android_Data_Exfiltration",
            "tags": ["data_exfil"],
            "authoritative": False,
            "confidence": 0.05,
        }
    ]
    result.composite_risk_score, result.composite_risk_level = _compute_composite_risk(result)
    assert result.composite_risk_score < 10
    assert _compute_verdict(result) == "CLEAN"


def test_requested_tools_without_supported_inputs_are_skipped(tmp_path: Path) -> None:
    artifact = tmp_path / "device_info.txt"
    artifact.write_text("ro.product.model=test", encoding="utf-8")
    result = analyze(
        {"device_info": artifact},
        run_mvt=True,
        run_capa=True,
        run_apkid=True,
        run_quark=True,
        run_intel=True,
        run_browser=True,
    )
    for tool in ("mvt", "capa", "apkid", "quark", "intel", "browser"):
        assert result.tool_status[tool] == "skipped_no_input"
