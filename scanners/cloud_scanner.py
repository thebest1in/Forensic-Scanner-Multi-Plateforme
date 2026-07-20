import subprocess
import json
from pathlib import Path

from core.base_scanner import BaseScanner, ScanResult
from core.scanner_registry import ScannerRegistry


@ScannerRegistry.register
class CloudScanner(BaseScanner):
    """Cloud infrastructure forensic scanner (AWS, Azure, GCP)."""

    def __init__(self, provider: str = "aws", profile: str = "deep", **kwargs):
        super().__init__(name="Cloud Forensic Scanner", platform="cloud")
        self.provider = provider.lower()
        self.profile = profile

    def _run_cmd(self, cmd: str, timeout: int = 15) -> tuple[bool, str]:
        try:
            r = subprocess.run(
                cmd, shell=True, capture_output=True, text=True,
                timeout=timeout, encoding="utf-8", errors="replace",
            )
            return r.returncode == 0, r.stdout.strip() or r.stderr.strip()
        except Exception as e:
            return False, str(e)

    def collect_artifacts(self, target: str, output_dir: Path) -> list[dict]:
        output_dir.mkdir(parents=True, exist_ok=True)
        artifacts = []
        if self.provider == "aws":
            artifacts = self._collect_aws(output_dir)
        elif self.provider == "azure":
            artifacts = self._collect_azure(output_dir)
        elif self.provider == "gcp":
            artifacts = self._collect_gcp(output_dir)
        return artifacts

    def _collect_aws(self, output_dir: Path) -> list[dict]:
        artifacts = []
        aws_cmds = {
            "iam_users": "aws iam list-users --output json 2>/dev/null",
            "iam_roles": "aws iam list-roles --output json 2>/dev/null",
            "s3_buckets": "aws s3api list-buckets --output json 2>/dev/null",
            "ec2_instances": "aws ec2 describe-instances --output json 2>/dev/null",
            "security_groups": "aws ec2 describe-security-groups --output json 2>/dev/null",
            "cloudtrail": "aws cloudtrail lookup-events --max-results 100 --output json 2>/dev/null",
            "vpc_flow_logs": "aws ec2 describe-flow-logs --output json 2>/dev/null",
            "route53": "aws route53 list-hosted-zones --output json 2>/dev/null",
            "rds_instances": "aws rds describe-db-instances --output json 2>/dev/null",
            "lambda_functions": "aws lambda list-functions --output json 2>/dev/null",
        }
        items = list(aws_cmds.items())
        for i, (key, cmd) in enumerate(items):
            self._report_progress((i / len(items)) * 50, f"AWS: Collecting {key}")
            ok, data = self._run_cmd(cmd)
            fpath = output_dir / f"aws_{key}.json"
            fpath.write_text(data if ok and data else "{}", encoding="utf-8")
            artifacts.append({"id": f"aws_{key}", "file": str(fpath), "desc": f"AWS {key.replace('_', ' ').title()}", "size": fpath.stat().st_size})
        return artifacts

    def _collect_azure(self, output_dir: Path) -> list[dict]:
        artifacts = []
        azure_cmds = {
            "resource_groups": "az group list --output json 2>/dev/null",
            "virtual_machines": "az vm list --output json 2>/dev/null",
            "storage_accounts": "az storage account list --output json 2>/dev/null",
            "nsg_rules": "az network nsg list --output json 2>/dev/null",
            "activity_log": "az monitor activity-log list --max-events 100 --output json 2>/dev/null",
            "ad_users": "az ad user list --output json 2>/dev/null",
            "key_vaults": "az keyvault list --output json 2>/dev/null",
        }
        items = list(azure_cmds.items())
        for i, (key, cmd) in enumerate(items):
            self._report_progress((i / len(items)) * 50, f"Azure: Collecting {key}")
            ok, data = self._run_cmd(cmd)
            fpath = output_dir / f"azure_{key}.json"
            fpath.write_text(data if ok and data else "{}", encoding="utf-8")
            artifacts.append({"id": f"azure_{key}", "file": str(fpath), "desc": f"Azure {key.replace('_', ' ').title()}", "size": fpath.stat().st_size})
        return artifacts

    def _collect_gcp(self, output_dir: Path) -> list[dict]:
        artifacts = []
        gcp_cmds = {
            "projects": "gcloud projects list --format json 2>/dev/null",
            "instances": "gcloud compute instances list --format json 2>/dev/null",
            "firewall_rules": "gcloud compute firewall-rules list --format json 2>/dev/null",
            "iam_bindings": "gcloud projects get-iam-policy --format json 2>/dev/null",
            "audit_logs": "gcloud logging read 'protoPayload.serviceName=cloudresourcemanager.googleapis.com' --limit 100 --format json 2>/dev/null",
        }
        items = list(gcp_cmds.items())
        for i, (key, cmd) in enumerate(items):
            self._report_progress((i / len(items)) * 50, f"GCP: Collecting {key}")
            ok, data = self._run_cmd(cmd)
            fpath = output_dir / f"gcp_{key}.json"
            fpath.write_text(data if ok and data else "{}", encoding="utf-8")
            artifacts.append({"id": f"gcp_{key}", "file": str(fpath), "desc": f"GCP {key.replace('_', ' ').title()}", "size": fpath.stat().st_size})
        return artifacts

    def analyze_artifacts(self, artifacts: list[dict], output_dir: Path) -> list[dict]:
        threats = []
        cloud_indicators = ["root_user", "overprivileged", "public_access", "unencrypted", "exposed_key"]
        for art in artifacts:
            fpath = Path(art["file"])
            if not fpath.exists():
                continue
            try:
                content = fpath.read_text(encoding="utf-8", errors="replace").lower()
                for ind in cloud_indicators:
                    if ind in content:
                        threats.append({
                            "type": "cloud_misconfiguration",
                            "indicator": ind,
                            "source": art["id"],
                            "severity": "suspicious",
                        })
            except Exception:
                continue
        return threats

    def get_capabilities(self) -> list[str]:
        return ["iam_audit", "storage_analysis", "network_security", "audit_log_review", "misconfiguration_detection"]
