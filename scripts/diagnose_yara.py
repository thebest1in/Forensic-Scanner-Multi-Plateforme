import argparse
import json
from collections import Counter
from pathlib import Path

import yara

from yara_diagnostics import collect_match_evidence


def main() -> int:
    parser = argparse.ArgumentParser(description="Capture exact YARA string evidence for one local artifact")
    parser.add_argument("artifact", type=Path)
    parser.add_argument("--rules", type=Path, default=Path("rules/poco_rules.yar"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    artifact = args.artifact.resolve()
    data = artifact.read_bytes()
    rules = yara.compile(filepath=str(args.rules.resolve()))
    matches = rules.match(data=data)
    evidence = [
        record
        for match in matches
        for record in collect_match_evidence(match, artifact, data)
    ]
    counts = Counter((item["rule"], item["string_identifier"]) for item in evidence)
    report = {
        "artifact": str(artifact),
        "artifact_size": len(data),
        "rules_file": str(args.rules.resolve()),
        "matched_rules": [match.rule for match in matches],
        "string_match_counts": [
            {"rule": rule, "string_identifier": identifier, "count": count}
            for (rule, identifier), count in sorted(counts.items())
        ],
        "evidence": evidence,
    }
    payload = json.dumps(report, indent=2, ensure_ascii=False)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8")
        print(f"Wrote {len(evidence)} string matches to {args.output}")
    else:
        print(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
