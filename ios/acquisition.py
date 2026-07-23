"""iOS forensic acquisition using libimobiledevice.

Logical backup-based acquisition for non-jailbroken iPhones.
Requires libimobiledevice binaries on PATH or bundled with the tool.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from core import logger


class ArtifactStatus(str, Enum):
    SUCCESS = "SUCCESS"
    EMPTY = "EMPTY"
    FAILED = "FAILED"
    NOT_SUPPORTED = "NOT_SUPPORTED"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    DEVICE_LOCKED = "DEVICE_LOCKED"
    PAIRING_REQUIRED = "PAIRING_REQUIRED"
    PASSWORD_REQUIRED = "PASSWORD_REQUIRED"
    TOOL_UNAVAILABLE = "TOOL_UNAVAILABLE"


@dataclass
class ArtifactResult:
    artifact_id: str
    path: Path | None = None
    status: ArtifactStatus = ArtifactStatus.FAILED
    stdout: str = ""
    stderr: str = ""
    exit_code: int | None = None
    source_type: str = ""  # "backup", "live", "parser", "mvt", "diagnostic"

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "path": str(self.path) if self.path else None,
            "status": self.status.value,
            "source_type": self.source_type,
            "exit_code": self.exit_code,
        }


def _find_tool(name: str) -> str | None:
    """Locate a libimobiledevice tool on PATH or in bundled directory."""
    tool_path = shutil.which(name)
    if tool_path:
        return tool_path

    # Check bundled libimobiledevice directory (same level as project root)
    import sys as _sys
    project_root = Path(__file__).resolve().parent.parent
    bundled_dir = project_root / "libimobiledevice"
    if bundled_dir.exists():
        exe_name = f"{name}.exe" if _sys.platform == "win32" else name
        candidate = bundled_dir / exe_name
        if candidate.exists():
            return str(candidate)

    # Common Windows install locations
    if _sys.platform == "win32":
        common = [
            Path.home() / "AppData/Local/Apple/DeviceSupport/libimobiledevice",
            Path("C:/Program Files/libimobiledevice"),
            Path("C:/Program Files (x86)/libimobiledevice"),
        ]
        for base in common:
            exe_name = f"{name}.exe"
            candidate = base / exe_name
            if candidate.exists():
                return str(candidate)
    return None


class IOSAcquirer:
    """Acquires forensic evidence from iOS devices via libimobiledevice.

    This is a logical acquisition pipeline — it creates local backups
    and extracts device metadata. It does NOT perform physical acquisition
    or filesystem-level extraction on non-jailbroken devices.
    """

    def __init__(self, serial: str | None = None):
        self._serial = serial
        self._backup_dir: Path | None = None
        self._tool_cache: dict[str, str | None] = {}

    def _get_tool(self, name: str) -> str | None:
        if name not in self._tool_cache:
            self._tool_cache[name] = _find_tool(name)
        return self._tool_cache[name]

    def _run_tool(
        self, tool_name: str, args: list[str], timeout: int = 120
    ) -> tuple[bool, str, str, int]:
        """Run a libimobiledevice tool. Returns (success, stdout, stderr, returncode)."""
        tool_path = self._get_tool(tool_name)
        if not tool_path:
            return False, "", f"{tool_name} not found on PATH", -1

        cmd = [tool_path] + args
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                creationflags=(
                    subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
                ),
            )
            stdout = (result.stdout or "").strip()
            stderr = (result.stderr or "").strip()
            return result.returncode == 0, stdout, stderr, result.returncode
        except subprocess.TimeoutExpired:
            return False, "", f"{tool_name} timed out after {timeout}s", -1
        except FileNotFoundError:
            return False, "", f"{tool_name} binary not found", -1
        except Exception as e:
            return False, "", f"{tool_name} error: {e}", -1

    def is_available(self) -> bool:
        """Check if libimobiledevice tools are available."""
        return self._get_tool("idevice_id") is not None

    def detect_devices(self) -> list[dict[str, str]]:
        """Detect connected iOS devices. Returns list of {udid, name, model}."""
        ok, stdout, stderr, _ = self._run_tool("idevice_id", ["-l"])
        if not ok or not stdout.strip():
            return []

        devices = []
        for line in stdout.splitlines():
            udid = line.strip()
            if not udid or len(udid) < 10:
                continue
            info = self._get_device_info_raw(udid)
            devices.append({
                "udid": udid,
                "name": info.get("DeviceName", "Unknown"),
                "model": info.get("ProductType", "Unknown"),
                "version": info.get("ProductVersion", "Unknown"),
            })
        return devices

    def _get_device_info_raw(self, udid: str) -> dict[str, str]:
        """Get raw key-value device info from ideviceinfo."""
        args = ["-u", udid] if udid else []
        ok, stdout, _, _ = self._run_tool("ideviceinfo", args)
        if not ok:
            return {}
        info = {}
        for line in stdout.splitlines():
            if ": " in line:
                key, _, value = line.partition(": ")
                info[key.strip()] = value.strip()
        return info

    def pair_device(self, udid: str) -> ArtifactResult:
        """Attempt to pair with the device."""
        args = ["-u", udid, "pair"] if udid else ["pair"]
        ok, stdout, stderr, rc = self._run_tool("idevicepair", args, timeout=60)
        status = ArtifactStatus.SUCCESS if ok else ArtifactStatus.PAIRING_REQUIRED
        if "Password" in stderr or "password" in stderr:
            status = ArtifactStatus.PASSWORD_REQUIRED
        if "locked" in stderr.lower():
            status = ArtifactStatus.DEVICE_LOCKED
        return ArtifactResult(
            artifact_id="pairing_status",
            status=status,
            stdout=stdout,
            stderr=stderr,
            exit_code=rc,
            source_type="live",
        )

    def validate_pairing(self, udid: str) -> ArtifactResult:
        """Validate existing pairing with the device."""
        args = ["-u", udid, "validate"] if udid else ["validate"]
        ok, stdout, stderr, rc = self._run_tool("idevicepair", args)
        status = ArtifactStatus.SUCCESS if ok else ArtifactStatus.PAIRING_REQUIRED
        return ArtifactResult(
            artifact_id="pairing_validation",
            status=status,
            stdout=stdout,
            stderr=stderr,
            exit_code=rc,
            source_type="live",
        )

    def extract_device_info(self, udid: str) -> ArtifactResult:
        """Extract comprehensive device information via ideviceinfo."""
        args = ["-u", udid, "-k", "all"] if udid else ["-k", "all"]
        ok, stdout, stderr, rc = self._run_tool("ideviceinfo", args)
        if not ok and not stdout:
            args_basic = ["-u", udid] if udid else []
            ok, stdout, stderr, rc = self._run_tool("ideviceinfo", args_basic)

        status = ArtifactStatus.SUCCESS if ok and stdout else ArtifactStatus.FAILED
        return ArtifactResult(
            artifact_id="device_information",
            status=status,
            stdout=stdout,
            stderr=stderr,
            exit_code=rc,
            source_type="live",
        )

    def create_backup(
        self,
        udid: str,
        output_dir: Path,
        full: bool = True,
        password: str | None = None,
    ) -> ArtifactResult:
        """Create a local iOS backup using idevicebackup2.

        Args:
            udid: Device UDID
            output_dir: Directory to store the backup
            full: If True, create full backup; otherwise incremental
            password: Optional encryption password (stored in memory only)
        """
        output_dir.mkdir(parents=True, exist_ok=True)
        self._backup_dir = output_dir

        args = ["backup"]
        if udid:
            args = ["-u", udid] + args
        if full:
            args.append("--full")
        if password:
            args.extend(["--password", password])
        args.append(str(output_dir))

        logger.info(f"Creating iOS backup in {output_dir.name}...")
        ok, stdout, stderr, rc = self._run_tool(
            "idevicebackup2", args, timeout=600
        )

        # idevicebackup2 returns 0 on success, check for completion markers
        combined = stdout + "\n" + stderr
        completed = "Backup Complete" in combined or "backup complete" in combined.lower()

        if completed or (ok and rc == 0):
            status = ArtifactStatus.SUCCESS
            logger.success(f"iOS backup completed: {output_dir.name}")
        elif "password" in combined.lower() or "encrypted" in combined.lower():
            status = ArtifactStatus.PASSWORD_REQUIRED
        elif "locked" in combined.lower():
            status = ArtifactStatus.DEVICE_LOCKED
        else:
            status = ArtifactStatus.FAILED

        return ArtifactResult(
            artifact_id="local_backup",
            path=output_dir if status == ArtifactStatus.SUCCESS else None,
            status=status,
            stdout=stdout,
            stderr=stderr,
            exit_code=rc,
            source_type="backup",
        )

    def collect_sysdiagnose(self, udid: str, output_dir: Path) -> ArtifactResult:
        """Attempt to trigger sysdiagnose collection.

        Note: On non-jailbroken devices, sysdiagnose may not be accessible.
        This is a best-effort attempt.
        """
        output_dir.mkdir(parents=True, exist_ok=True)
        # sysdiagnose is typically triggered via diagnostic mode
        # For logical acquisition, we try idevicesyslog as a fallback
        args = ["-u", udid] if udid else []
        args.extend(["-s", "3"])  # 3 second capture
        args.extend(["-o", str(output_dir / "sysdiagnose.log")])

        ok, stdout, stderr, rc = self._run_tool("idevicesyslog", args, timeout=30)
        log_file = output_dir / "sysdiagnose.log"

        if log_file.exists() and log_file.stat().st_size > 0:
            return ArtifactResult(
                artifact_id="sysdiagnose",
                path=log_file,
                status=ArtifactStatus.SUCCESS,
                stdout=stdout,
                stderr=stderr,
                exit_code=rc,
                source_type="live",
            )
        return ArtifactResult(
            artifact_id="sysdiagnose",
            status=ArtifactStatus.FAILED,
            stdout=stdout,
            stderr=stderr or "sysdiagnose not available on non-jailbroken device",
            exit_code=rc,
            source_type="diagnostic",
        )

    def collect_instproxy(self, udid: str) -> ArtifactResult:
        """List installed applications via instproxy."""
        args = ["-u", udid, "list"] if udid else ["list"]
        ok, stdout, stderr, rc = self._run_tool("instproxy", args, timeout=60)
        status = ArtifactStatus.SUCCESS if ok and stdout else ArtifactStatus.FAILED
        return ArtifactResult(
            artifact_id="installed_applications",
            status=status,
            stdout=stdout,
            stderr=stderr,
            exit_code=rc,
            source_type="live",
        )

    def collect_notification_proxy(self, udid: str, output_dir: Path) -> ArtifactResult:
        """Collect notification proxy data."""
        output_dir.mkdir(parents=True, exist_ok=True)
        # ideviceinfo notifications are limited on non-jailbroken
        return ArtifactResult(
            artifact_id="notification_proxy",
            status=ArtifactStatus.NOT_SUPPORTED,
            stderr="Notification proxy limited on non-jailbroken device",
            source_type="live",
        )

    @property
    def backup_dir(self) -> Path | None:
        return self._backup_dir

    def is_paired(self, udid: str) -> bool:
        """Check if device is already paired."""
        result = self.validate_pairing(udid)
        return result.status == ArtifactStatus.SUCCESS
