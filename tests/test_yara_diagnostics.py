from pathlib import Path
from types import SimpleNamespace

from yara_diagnostics import collect_match_evidence


def test_collect_match_evidence_includes_offsets_and_context(tmp_path: Path) -> None:
    artifact = tmp_path / "bugreport-device.txt"
    data = b"before diagnostic upload after"
    artifact.write_bytes(data)
    instance = SimpleNamespace(offset=18, matched_data=b"upload")
    string_match = SimpleNamespace(identifier="$e1", instances=[instance])
    match = SimpleNamespace(
        rule="Android_Data_Exfiltration",
        namespace="default",
        tags=["data_exfil"],
        meta={"severity": "high"},
        strings=[string_match],
    )

    evidence = collect_match_evidence(match, artifact, data, context_bytes=20)

    assert evidence[0]["string_identifier"] == "$e1"
    assert evidence[0]["offset"] == 18
    assert evidence[0]["matched_value_preview"] == "upload"
    assert evidence[0]["context_before"] == "before diagnostic"
    assert evidence[0]["context_after"] == "after"
    assert evidence[0]["artifact_type"] == "android_bugreport_aggregate"
