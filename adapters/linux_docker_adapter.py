import json
import time
from pathlib import Path

import core
from adapters.base_adapter import BaseAdapter, DeviceInfo, AdapterRegistry


class LinuxDockerAdapter(BaseAdapter):
    """Linux server & Docker container forensic adapter.

    Supports two modes:
    1. SSH mode: Connect to remote Linux servers via SSH
    2. Docker mode: Inspect local/remote Docker containers

    Inspired by YaraHunter architecture — extracts artifacts for YARA scanning.
    """

    @property
    def name(self) -> str:
        return "Linux / Docker"

    @property
    def os_type(self) -> str:
        return "linux"

    def can_handle(self, serial: str) -> bool:
        """Check if Docker is available locally or serial looks like a hostname."""
        if serial.startswith("docker:"):
            try:
                import docker
                client = docker.from_env()
                client.ping()
                return True
            except Exception:
                return False
        if serial.startswith("ssh:"):
            return True
        return False

    def get_device_info(self, serial: str = "") -> DeviceInfo:
        info = DeviceInfo(os_type="linux", adapter_name=self.name, serial=serial)
        if serial.startswith("docker:"):
            container_id = serial.replace("docker:", "")
            try:
                import docker
                client = docker.from_env()
                container = client.containers.get(container_id)
                info.brand = "Docker"
                info.model = container.image.tags[0] if container.image.tags else container.image.short_id
                info.product = f"Container: {container.name}"
                info.android_version = ""
            except Exception as e:
                core.logger.warning(f"Docker info failed: {e}")
        elif serial.startswith("ssh:"):
            host = serial.replace("ssh:", "")
            info.brand = "Linux"
            info.model = f"Remote: {host}"
            info.product = "SSH"
        return info

    def extract(self, serial: str = "", profile: str = "triage", on_progress=None) -> dict[str, str]:
        manifest_path = Path(__file__).resolve().parent.parent / "manifests" / "linux_artifacts.json"
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)

        profile_cmds = manifest.get("profiles", {}).get(profile, {}).get("commands", [])
        if not profile_cmds:
            core.logger.error(f"Linux profile '{profile}' not found")
            return {}

        dump_dir = core.create_dump_dir()
        extracted = {}
        total = len(profile_cmds)

        is_docker = serial.startswith("docker:")
        container_id = serial.replace("docker:", "") if is_docker else ""
        ssh_host = serial.replace("ssh:", "") if serial.startswith("ssh:") else ""

        for i, cmd in enumerate(profile_cmds):
            cmd_id = cmd["id"]
            linux_cmd = cmd.get("linux_cmd", "")
            output_file = cmd["output_file"]
            desc = cmd.get("description", f"Extracting {cmd_id}...")

            if on_progress:
                pct = int((i / total) * 100)
                on_progress(pct, desc)

            core.logger.info(f"[{i+1}/{total}] {desc}")

            try:
                content = _run_linux_cmd(
                    linux_cmd, is_docker=is_docker,
                    container_id=container_id, ssh_host=ssh_host,
                )
                if content:
                    out_path = dump_dir / output_file
                    out_path.write_text(content, encoding="utf-8", errors="replace")
                    extracted[cmd_id] = str(out_path)
                    core.logger.info(f"Extracted: {cmd_id} -> {output_file}")
                else:
                    core.logger.warning(f"Extraction empty: {cmd_id}")
            except Exception as e:
                core.logger.warning(f"Extraction failed for {cmd_id}: {e}")

        if on_progress:
            on_progress(100, f"Linux extraction complete. {len(extracted)} artifacts.")
        core.logger.info(f"Linux extraction complete. {len(extracted)} artifacts in {dump_dir.name}")
        return extracted

    def get_profiles(self) -> dict[str, dict]:
        manifest_path = Path(__file__).resolve().parent.parent / "manifests" / "linux_artifacts.json"
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)

        profiles = {}
        for key, val in manifest.get("profiles", {}).items():
            profiles[key] = {
                "name": val.get("name", key),
                "description": val.get("description", ""),
                "count": len(val.get("commands", [])),
            }
        return profiles


def _run_linux_cmd(cmd: str, is_docker: bool = False,
                   container_id: str = "", ssh_host: str = "") -> str | None:
    """Execute a command on a Linux target (Docker container or SSH host)."""
    import subprocess

    try:
        if is_docker and container_id:
            full_cmd = f'docker exec {container_id} sh -c "{cmd}"'
        elif ssh_host:
            full_cmd = f'ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no {ssh_host} "{cmd}"'
        else:
            return None

        result = subprocess.run(
            full_cmd, shell=True, capture_output=True,
            text=True, encoding="utf-8", errors="replace",
            timeout=60,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
        return None

    except subprocess.TimeoutExpired:
        core.logger.warning(f"Linux command timed out: {cmd}")
        return None
    except Exception as e:
        core.logger.warning(f"Linux command failed: {e}")
        return None


AdapterRegistry.register(LinuxDockerAdapter())
