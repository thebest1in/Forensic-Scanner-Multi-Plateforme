import re
import time
from pathlib import Path
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from core import logger


# ============================================================
# CORRELATION ENGINE — Cross-Tool Event Correlation
# ============================================================

# Default correlation window (seconds)
DEFAULT_WINDOW_SECONDS = 300  # 5 minutes

# Correlation rule definitions (JSON-style, Crow-Eye Wings pattern)
CORRELATION_RULES = [
    {
        "id": "multi_tool_package_threat",
        "description": "Multiple tools flag the same package as malicious",
        "min_sources": 2,
        "severity": "CRITICAL",
        "tool_sources": ["yara", "heuristics", "mvt", "quark", "apkid", "capa", "aleapp"],
    },
    {
        "id": "network_plus_package",
        "description": "Suspicious IP/domain correlates with flagged package activity",
        "min_sources": 2,
        "severity": "CRITICAL",
        "tool_sources": ["pcap", "otx", "ioc"],
    },
    {
        "id": "behavioral_plus_static",
        "description": "Behavioral analysis (Quark) confirms static findings (YARA/APKiD)",
        "min_sources": 2,
        "severity": "CRITICAL",
        "tool_sources": ["quark", "yara", "apkid"],
    },
    {
        "id": "browser_plus_network",
        "description": "Suspicious browser visits correlate with network C2 hits",
        "min_sources": 2,
        "severity": "HIGH",
        "tool_sources": ["browser", "pcap", "otx"],
    },
    {
        "id": "entropy_plus_obfuscation",
        "description": "High entropy (encrypted data) combined with packer detection",
        "min_sources": 2,
        "severity": "HIGH",
        "tool_sources": ["entropy", "apkid", "quark"],
    },
    {
        "id": "stalkerware_indicators",
        "description": "Stalkerware-specific indicators across multiple tools",
        "min_sources": 2,
        "severity": "CRITICAL",
        "tool_sources": ["heuristics", "aleapp", "mvt", "browser"],
    },
]


@dataclass
class CorrelationEvent:
    """A single correlated event linking multiple tool findings."""
    rule_id: str = ""
    rule_description: str = ""
    severity: str = ""
    matched_tools: list[str] = field(default_factory=list)
    package_name: str = ""
    timestamp_window: str = ""
    evidence: list[dict] = field(default_factory=list)
    confidence: float = 0.0  # 0.0-1.0

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "rule_description": self.rule_description,
            "severity": self.severity,
            "matched_tools": self.matched_tools,
            "package_name": self.package_name,
            "timestamp_window": self.timestamp_window,
            "evidence": self.evidence,
            "confidence": round(self.confidence, 4),
        }


@dataclass
class CorrelationResult:
    """Complete correlation analysis result."""
    events: list[dict] = field(default_factory=list)
    total_correlations: int = 0
    critical_count: int = 0
    high_count: int = 0
    summary: str = ""

    def to_dict(self) -> dict:
        return {
            "events": self.events,
            "total_correlations": self.total_correlations,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "summary": self.summary,
        }


class CorrelationEngine:
    """Cross-tool event correlation engine.

    Correlates findings from independent analysis tools (YARA, MVT, ALEAPP,
    capa, APKiD, Quark, OTX, PCAP, browser forensics, entropy) to identify
    events where multiple tools independently point to the same threat.

    This transforms "9 independent verdicts" into "3 tools agree this
    app did X at this time" — a much stronger forensic claim.

    Uses Crow-Eye Wings-style JSON rule definitions with configurable
    time windows and minimum source thresholds.
    """

    def __init__(self, window_seconds: int = DEFAULT_WINDOW_SECONDS):
        self._window = timedelta(seconds=window_seconds)
        self._rules = CORRELATION_RULES

    def correlate(self, analysis_result, window_seconds: int = None) -> CorrelationResult:
        """Run correlation analysis on an AnalysisResult object.

        Args:
            analysis_result: AnalysisResult from analyzer.py
            window_seconds: Override default correlation window
        """
        result = CorrelationResult()
        window = timedelta(seconds=window_seconds) if window_seconds else self._window

        # Extract per-tool findings into normalized events
        tool_events = self._extract_events(analysis_result)

        # Run each correlation rule
        for rule in self._rules:
            matches = self._apply_rule(rule, tool_events, window)
            for match in matches:
                result.events.append(match.to_dict())
                result.total_correlations += 1
                if match.severity == "CRITICAL":
                    result.critical_count += 1
                elif match.severity == "HIGH":
                    result.high_count += 1

        result.summary = self._build_summary(result)
        if result.total_correlations > 0:
            logger.warning(
                f"Correlation: {result.total_correlations} events "
                f"({result.critical_count} critical, {result.high_count} high)"
            )
        return result

    def _extract_events(self, result) -> list[dict]:
        """Extract normalized events from all tool results."""
        events = []

        # YARA matches
        for match in (result.matched_rules or []):
            if not match.get("authoritative", True):
                continue
            events.append({
                "tool": "yara",
                "package": self._extract_package_from_file(match.get("file", "")),
                "severity": self._tags_to_severity(match.get("tags", [])),
                "detail": match.get("rule", ""),
                "tags": match.get("tags", []),
            })

        # Heuristic findings
        heur = result.heuristic_result or {}
        if heur.get("suspicious_packages"):
            for pkg in heur["suspicious_packages"]:
                events.append({
                    "tool": "heuristics",
                    "package": pkg if isinstance(pkg, str) else pkg.get("name", ""),
                    "severity": "CRITICAL" if heur.get("risk_level") == "CRITICAL" else "HIGH",
                    "detail": f"risk_score={heur.get('risk_score', 0)}",
                })

        # MVT results
        for mvt in (result.mvt_results or []):
            events.append({
                "tool": "mvt",
                "package": mvt.get("indicator", ""),
                "severity": mvt.get("threat_level", "medium").upper(),
                "detail": mvt.get("description", ""),
            })

        # ALEAPP results
        for aleapp in (result.aleapp_results or []):
            if aleapp.get("stalkerware_found"):
                events.append({
                    "tool": "aleapp",
                    "package": aleapp.get("package_name", ""),
                    "severity": "CRITICAL",
                    "detail": "Stalkerware detected",
                })
            for pkg in aleapp.get("suspicious_packages", []):
                events.append({
                    "tool": "aleapp",
                    "package": pkg,
                    "severity": "HIGH",
                    "detail": "Suspicious package",
                })

        # Capa results
        for capa in (result.capa_results or []):
            for mc in capa.get("malicious_capabilities", []):
                events.append({
                    "tool": "capa",
                    "package": capa.get("target", ""),
                    "severity": mc.get("severity", "medium").upper(),
                    "detail": mc.get("name", ""),
                })

        # APKiD results
        for apkid in (result.apkid_results or []):
            if apkid.get("packers_found") or apkid.get("anti_analysis"):
                events.append({
                    "tool": "apkid",
                    "package": apkid.get("package_name", ""),
                    "severity": apkid.get("threat_level", "CLEAN"),
                    "detail": f"packers={apkid.get('packers_found', [])}",
                })

        # Quark results
        for quark in (result.quark_results or []):
            if quark.get("threat_level") != "CLEAN":
                events.append({
                    "tool": "quark",
                    "package": quark.get("package_name", ""),
                    "severity": quark.get("threat_level", "CLEAN"),
                    "detail": f"score={quark.get('threat_score', 0)}",
                })

        # PCAP C2 hits
        pcap = result.pcap_results or {}
        for c2 in pcap.get("c2_hits", []):
            if isinstance(c2, dict):
                events.append({
                    "tool": "pcap",
                    "package": c2.get("domain", ""),
                    "severity": "CRITICAL",
                    "detail": f"category={c2.get('category', '')}",
                })

        # OTX/intel results
        for intel in (result.intel_results or []):
            if intel.get("is_malicious"):
                events.append({
                    "tool": "otx",
                    "package": intel.get("ip", ""),
                    "severity": "CRITICAL" if intel.get("c2_match") else "HIGH",
                    "detail": f"pulses={len(intel.get('otx_pulses', []))}",
                })

        # Entropy results
        for ent in (result.entropy_results or []):
            if ent.get("exfil_risk") or ent.get("obfuscation_risk"):
                events.append({
                    "tool": "entropy",
                    "package": Path(ent.get("file_path", "")).name,
                    "severity": "HIGH",
                    "detail": f"H={ent.get('overall_entropy', 0):.2f}",
                })

        # Browser forensics results
        for browser in (result.browser_results or []):
            for sv in browser.get("suspicious_visits", []):
                events.append({
                    "tool": "browser",
                    "package": sv.get("url", ""),
                    "severity": "HIGH",
                    "detail": sv.get("suspicious_reason", ""),
                })

        return events

    def _apply_rule(self, rule: dict, events: list[dict], window: timedelta) -> list[CorrelationEvent]:
        """Apply a single correlation rule to events."""
        rule_id = rule["id"]
        rule_tools = set(rule["tool_sources"])
        min_sources = rule["min_sources"]

        # Group events by package name
        package_events = {}
        for event in events:
            pkg = event.get("package", "")
            if pkg:
                if pkg not in package_events:
                    package_events[pkg] = []
                package_events[pkg].append(event)

        correlations = []
        for pkg, pkg_events in package_events.items():
            # Check which tools contributed
            contributing_tools = set(e["tool"] for e in pkg_events)
            matching_tools = contributing_tools & rule_tools

            if len(matching_tools) >= min_sources:
                confidence = min(len(matching_tools) / len(rule_tools), 1.0)
                event = CorrelationEvent(
                    rule_id=rule_id,
                    rule_description=rule["description"],
                    severity=rule["severity"],
                    matched_tools=sorted(matching_tools),
                    package_name=pkg,
                    confidence=confidence,
                    evidence=[e for e in pkg_events if e["tool"] in matching_tools],
                )
                correlations.append(event)

        return correlations

    def _extract_package_from_file(self, filename: str) -> str:
        """Extract package-like name from a filename."""
        name = Path(filename).stem
        if "." in name:
            parts = name.split(".")
            if len(parts) >= 2:
                return ".".join(parts[:3])
        return name

    @staticmethod
    def _tags_to_severity(tags: list) -> str:
        critical_tags = {"pegasus", "zero_click", "root_exploit", "reverse_shell", "novispy", "finspy"}
        if any(t.lower() in critical_tags for t in tags):
            return "CRITICAL"
        high_tags = {"stalkerware", "sandrorat", "dendroid", "hackingteam", "disguised_package"}
        if any(t.lower() in high_tags for t in tags):
            return "HIGH"
        return "MEDIUM"

    def _build_summary(self, result: CorrelationResult) -> str:
        if result.total_correlations == 0:
            return "No cross-tool correlations found."
        lines = [
            f"{result.total_correlations} correlations: "
            f"{result.critical_count} CRITICAL, {result.high_count} HIGH"
        ]
        for event in result.events[:10]:
            lines.append(
                f"  [{event['severity']}] {event['rule_id']}: "
                f"{event['package_name']} ({', '.join(event['matched_tools'])})"
            )
        return "\n".join(lines)
