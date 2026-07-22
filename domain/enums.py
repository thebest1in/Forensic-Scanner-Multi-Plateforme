from enum import StrEnum


class Platform(StrEnum):
    ANDROID = "android"
    IOS = "ios"
    WINDOWS = "windows"
    LINUX = "linux"
    DOCKER = "docker"
    CLOUD = "cloud"
    MACOS = "macos"
    NETWORK = "network"
    MEMORY = "memory"
    DISK = "disk"
    UNKNOWN = "unknown"


class ArtifactCategory(StrEnum):
    DEVICE_INFO = "device_info"
    LOG = "log"
    NETWORK = "network"
    APPLICATION = "application"
    DATABASE = "database"
    BROWSER = "browser"
    FILESYSTEM = "filesystem"
    MEMORY = "memory"
    ARCHIVE = "archive"
    OTHER = "other"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ScanStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Verdict(StrEnum):
    CLEAN = "clean"
    LOW_RISK = "low_risk"
    SUSPICIOUS = "suspicious"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class ExecutionType(StrEnum):
    IO_BOUND = "io_bound"
    CPU_BOUND = "cpu_bound"
    SUBPROCESS = "subprocess"
    SQLITE_SENSITIVE = "sqlite_sensitive"
    EXTERNAL_API = "external_api"


class AcquisitionProfile(StrEnum):
    TRIAGE = "triage"
    DEEP = "deep"
