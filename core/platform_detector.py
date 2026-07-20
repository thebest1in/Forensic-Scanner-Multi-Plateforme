import platform
import subprocess
import shutil
from dataclasses import dataclass
from enum import Enum


class PlatformType(Enum):
    WINDOWS = "windows"
    MACOS = "macos"
    LINUX = "linux"
    ANDROID = "android"
    IOS = "ios"
    UNKNOWN = "unknown"


class ConnectionType(Enum):
    LOCAL = "local"
    ADB = "adb"
    SSH = "ssh"
    DOCKER = "docker"
    IDEVICE = "idevice"
    REMOTE = "remote"


@dataclass
class PlatformInfo:
    platform_type: PlatformType
    version: str
    architecture: str
    hostname: str
    connection_type: ConnectionType
    details: dict

    def to_dict(self) -> dict:
        return {
            "platform_type": self.platform_type.value,
            "version": self.version,
            "architecture": self.architecture,
            "hostname": self.hostname,
            "connection_type": self.connection_type.value,
            "details": self.details,
        }


class PlatformDetector:
    """Detect and classify the target platform for forensic scanning."""

    @staticmethod
    def detect_local() -> PlatformInfo:
        system = platform.system().lower()
        if system == "windows":
            return PlatformInfo(
                platform_type=PlatformType.WINDOWS,
                version=platform.version(),
                architecture=platform.machine(),
                hostname=platform.node(),
                connection_type=ConnectionType.LOCAL,
                details={
                    "release": platform.release(),
                    "python_version": platform.python_version(),
                },
            )
        elif system == "darwin":
            return PlatformInfo(
                platform_type=PlatformType.MACOS,
                version=platform.mac_ver()[0],
                architecture=platform.machine(),
                hostname=platform.node(),
                connection_type=ConnectionType.LOCAL,
                details={"release": platform.release()},
            )
        elif system == "linux":
            info = PlatformDetector._get_linux_info()
            return PlatformInfo(
                platform_type=PlatformType.LINUX,
                version=info.get("version", platform.release()),
                architecture=platform.machine(),
                hostname=platform.node(),
                connection_type=ConnectionType.LOCAL,
                details=info,
            )
        return PlatformInfo(
            platform_type=PlatformType.UNKNOWN,
            version=platform.platform(),
            architecture=platform.machine(),
            hostname=platform.node(),
            connection_type=ConnectionType.LOCAL,
            details={},
        )

    @staticmethod
    def detect_adb() -> PlatformInfo | None:
        adb_path = shutil.which("adb")
        if not adb_path:
            return None
        try:
            result = subprocess.run(
                [adb_path, "shell", "getprop", "ro.build.version.release"],
                capture_output=True, text=True, timeout=10,
            )
            android_version = result.stdout.strip()
            result2 = subprocess.run(
                [adb_path, "shell", "getprop", "ro.product.model"],
                capture_output=True, text=True, timeout=10,
            )
            model = result2.stdout.strip()
            return PlatformInfo(
                platform_type=PlatformType.ANDROID,
                version=android_version,
                architecture="arm64-v8a",
                hostname=model,
                connection_type=ConnectionType.ADB,
                details={"model": model, "android_version": android_version},
            )
        except Exception:
            return None

    @staticmethod
    def detect_ssh(target: str) -> PlatformInfo | None:
        if not target or not target.startswith("ssh:"):
            return None
        try:
            import paramiko
            parts = target.replace("ssh:", "").split("@")
            if len(parts) != 2:
                return None
            user, host = parts
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(host, username=user, timeout=10)
            stdin, stdout, stderr = client.exec_command("uname -a")
            uname = stdout.read().decode().strip()
            client.close()
            is_docker = "docker" in uname.lower() or "container" in uname.lower()
            return PlatformInfo(
                platform_type=PlatformType.LINUX,
                version=uname,
                architecture="remote",
                hostname=host,
                connection_type=ConnectionType.DOCKER if is_docker else ConnectionType.SSH,
                details={"uname": uname, "user": user, "host": host, "is_docker": is_docker},
            )
        except Exception:
            return None

    @staticmethod
    def detect_docker(container_id: str) -> PlatformInfo | None:
        try:
            result = subprocess.run(
                ["docker", "inspect", "--format", "{{.Config.Image}}", container_id],
                capture_output=True, text=True, timeout=10,
            )
            image = result.stdout.strip()
            return PlatformInfo(
                platform_type=PlatformType.LINUX,
                version=image,
                architecture="container",
                hostname=container_id[:12],
                connection_type=ConnectionType.DOCKER,
                details={"image": image, "container_id": container_id},
            )
        except Exception:
            return None

    @staticmethod
    def detect(target: str = "") -> PlatformInfo:
        if not target:
            return PlatformDetector.detect_local()
        if target.startswith("adb:"):
            info = PlatformDetector.detect_adb()
            return info or PlatformInfo(
                platform_type=PlatformType.ANDROID,
                version="unknown",
                architecture="unknown",
                hostname=target,
                connection_type=ConnectionType.ADB,
                details={},
            )
        if target.startswith("ssh:"):
            info = PlatformDetector.detect_ssh(target)
            return info or PlatformInfo(
                platform_type=PlatformType.UNKNOWN,
                version="unknown",
                architecture="unknown",
                hostname=target,
                connection_type=ConnectionType.SSH,
                details={},
            )
        if target.startswith("docker:"):
            container_id = target.replace("docker:", "")
            info = PlatformDetector.detect_docker(container_id)
            return info or PlatformInfo(
                platform_type=PlatformType.LINUX,
                version="unknown",
                architecture="container",
                hostname=container_id[:12],
                connection_type=ConnectionType.DOCKER,
                details={},
            )
        return PlatformDetector.detect_local()

    @staticmethod
    def _get_linux_info() -> dict:
        info = {}
        try:
            with open("/etc/os-release") as f:
                for line in f:
                    if "=" in line:
                        key, val = line.strip().split("=", 1)
                        info[key.lower()] = val.strip('"')
        except Exception:
            pass
        return info
