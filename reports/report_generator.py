import json
from pathlib import Path
from datetime import datetime


class ReportGenerator:
    """Generate forensic scan reports in multiple formats."""

    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_json_report(self, scan_results: list[dict], metadata: dict = None) -> Path:
        report = {
            "report_version": "1.0",
            "tool": "Forensic Scanner Multi-Plateforme",
            "generated": datetime.now().isoformat(),
            "metadata": metadata or {},
            "scan_results": scan_results,
            "summary": self._build_summary(scan_results),
        }
        path = self.output_dir / "forensic_report.json"
        path.write_text(json.dumps(report, indent=2, default=str, ensure_ascii=False), encoding="utf-8")
        return path

    def generate_html_report(self, scan_results: list[dict], metadata: dict = None) -> Path:
        summary = self._build_summary(scan_results)
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Forensic Scan Report</title>
<style>
body {{ font-family: 'Segoe UI', Tahoma, sans-serif; margin: 20px; background: #1a1a2e; color: #eee; }}
h1 {{ color: #3498db; border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
h2 {{ color: #e74c3c; margin-top: 30px; }}
.summary {{ background: #16213e; padding: 20px; border-radius: 10px; margin: 20px 0; }}
.summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; }}
.stat {{ background: #0f3460; padding: 15px; border-radius: 8px; text-align: center; }}
.stat-value {{ font-size: 2em; font-weight: bold; color: #3498db; }}
.stat-label {{ color: #aaa; font-size: 0.9em; }}
.threat-critical {{ color: #e74c3c; }}
.threat-suspicious {{ color: #f39c12; }}
.threat-clean {{ color: #2ecc71; }}
table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #333; }}
th {{ background: #0f3460; color: #3498db; }}
tr:hover {{ background: #16213e; }}
.severity-critical {{ background: #e74c3c; color: white; padding: 3px 8px; border-radius: 4px; }}
.severity-suspicious {{ background: #f39c12; color: black; padding: 3px 8px; border-radius: 4px; }}
.severity-clean {{ background: #2ecc71; color: white; padding: 3px 8px; border-radius: 4px; }}
</style>
</head>
<body>
<h1>Forensic Scanner Multi-Plateforme Report</h1>
<p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>

<div class="summary">
<h2>Summary</h2>
<div class="summary-grid">
<div class="stat"><div class="stat-value">{summary['total_scans']}</div><div class="stat-label">Scans Performed</div></div>
<div class="stat"><div class="stat-value threat-critical">{summary['critical_threats']}</div><div class="stat-label">Critical Threats</div></div>
<div class="stat"><div class="stat-value threat-suspicious">{summary['suspicious_threats']}</div><div class="stat-label">Suspicious Findings</div></div>
<div class="stat"><div class="stat-value">{summary['total_artifacts']}</div><div class="stat-label">Artifacts Collected</div></div>
</div>
</div>

<h2>Scan Results</h2>
<table>
<tr><th>Scanner</th><th>Platform</th><th>Status</th><th>Artifacts</th><th>Threats</th><th>Duration</th></tr>
"""
        for result in scan_results:
            status_class = f"severity-{result.get('status', 'clean').lower()}"
            html += f"""<tr>
<td>{result.get('scanner_name', 'Unknown')}</td>
<td>{result.get('platform', 'Unknown')}</td>
<td><span class="{status_class}">{result.get('status', 'Unknown')}</span></td>
<td>{result.get('artifact_count', 0)}</td>
<td>{result.get('threat_count', 0)}</td>
<td>{result.get('duration', 0):.1f}s</td>
</tr>"""
        html += "</table>"
        html += "</body></html>"
        path = self.output_dir / "forensic_report.html"
        path.write_text(html, encoding="utf-8")
        return path

    def generate_text_report(self, scan_results: list[dict], metadata: dict = None) -> Path:
        summary = self._build_summary(scan_results)
        lines = [
            "=" * 70,
            "  FORENSIC SCANNER MULTI-PLATEFORME REPORT",
            "=" * 70,
            f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"",
            f"  SUMMARY",
            f"  -------",
            f"  Total scans:      {summary['total_scans']}",
            f"  Critical threats: {summary['critical_threats']}",
            f"  Suspicious:       {summary['suspicious_threats']}",
            f"  Artifacts:        {summary['total_artifacts']}",
            f"",
            f"  SCAN RESULTS",
            f"  ------------",
        ]
        for result in scan_results:
            lines.extend([
                f"",
                f"  Scanner:  {result.get('scanner_name', 'Unknown')}",
                f"  Platform: {result.get('platform', 'Unknown')}",
                f"  Status:   {result.get('status', 'Unknown')}",
                f"  Artifacts: {result.get('artifact_count', 0)}",
                f"  Threats:  {result.get('threat_count', 0)}",
                f"  Duration: {result.get('duration', 0):.1f}s",
            ])
            if result.get("threats_detected"):
                lines.append(f"  Threats detected:")
                for t in result["threats_detected"][:10]:
                    lines.append(f"    [{t.get('severity', '?')}] {t.get('indicator', t.get('pattern', 'unknown'))}")
        lines.extend(["", "=" * 70])
        path = self.output_dir / "forensic_report.txt"
        path.write_text("\n".join(lines), encoding="utf-8")
        return path

    def _build_summary(self, scan_results: list[dict]) -> dict:
        total_scans = len(scan_results)
        critical = sum(1 for r in scan_results for t in r.get("threats_detected", []) if t.get("severity") == "critical")
        suspicious = sum(1 for r in scan_results for t in r.get("threats_detected", []) if t.get("severity") == "suspicious")
        total_artifacts = sum(r.get("artifact_count", 0) for r in scan_results)
        return {
            "total_scans": total_scans,
            "critical_threats": critical,
            "suspicious_threats": suspicious,
            "total_artifacts": total_artifacts,
        }
