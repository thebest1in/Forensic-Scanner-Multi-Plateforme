import json
from pathlib import Path
from typing import Any

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False


class YaraAnalyzer:
    """YARA rule-based malware and IOC scanning."""

    def __init__(self, rules_dir: str = ""):
        self.rules_dir = Path(rules_dir) if rules_dir else Path(__file__).parent.parent / "rules" / "yara"
        self._rules = None

    def load_rules(self) -> bool:
        if not YARA_AVAILABLE:
            return False
        rule_files = list(self.rules_dir.glob("*.yar")) + list(self.rules_dir.glob("*.yara"))
        if not rule_files:
            return False
        try:
            filepaths = {str(f): str(f) for f in rule_files}
            self._rules = yara.compile(filepaths=filepaths)
            return True
        except Exception:
            try:
                self._rules = yara.compile(filepath=str(rule_files[0]))
                return True
            except Exception:
                return False

    def scan_file(self, filepath: Path) -> list[dict]:
        if not self._rules and not self.load_rules():
            return []
        matches = []
        try:
            results = self._rules.match(str(filepath), timeout=30)
            for match in results:
                matches.append({
                    "rule": match.rule,
                    "tags": list(match.tags),
                    "meta": dict(match.meta) if match.meta else {},
                    "file": str(filepath.name),
                    "strings": [(s[0], s[1], s[2][:100]) for s in match.strings[:10]],
                })
        except Exception:
            pass
        return matches

    def scan_text(self, text: str) -> list[dict]:
        if not self._rules and not self.load_rules():
            return []
        matches = []
        try:
            results = self._rules.match(data=text.encode("utf-8"), timeout=30)
            for match in results:
                matches.append({
                    "rule": match.rule,
                    "tags": list(match.tags),
                    "meta": dict(match.meta) if match.meta else {},
                })
        except Exception:
            pass
        return matches

    def scan_directory(self, directory: Path) -> list[dict]:
        all_matches = []
        for f in directory.rglob("*"):
            if f.is_file() and f.stat().st_size < 50 * 1024 * 1024:
                file_matches = self.scan_file(f)
                all_matches.extend(file_matches)
        return all_matches
