from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class DeviceInfo:
    serial: str = ""
    brand: str = ""
    model: str = ""
    product: str = ""
    android_version: str = ""
    os_type: str = ""  # "android", "ios", "linux", "windows", "macos"
    adapter_name: str = ""

    @property
    def display_name(self) -> str:
        parts = [p for p in [self.brand, self.model] if p]
        return " ".join(parts) if parts else self.serial or "Unknown Device"

    @property
    def display_summary(self) -> str:
        parts = [self.display_name]
        if self.android_version:
            parts.append(f"Android {self.android_version}")
        if self.serial:
            parts.append(f"({self.serial})")
        return " — ".join(parts)


class BaseAdapter(ABC):
    """Abstract base class for all device adapters.

    Each adapter is responsible for:
    - Detecting if it can handle a connected device
    - Extracting forensic artifacts from the device
    - Providing device info for display in the GUI
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable adapter name (e.g., 'Android ADB', 'iOS')."""

    @property
    @abstractmethod
    def os_type(self) -> str:
        """OS type identifier: 'android', 'ios', 'linux', 'windows'."""

    @abstractmethod
    def can_handle(self, serial: str) -> bool:
        """Return True if this adapter can work with the given device serial."""

    @abstractmethod
    def get_device_info(self, serial: str) -> DeviceInfo:
        """Query and return device information."""

    @abstractmethod
    def extract(self, serial: str, profile: str, on_progress=None) -> dict[str, str]:
        """Extract forensic artifacts. Returns dict of artifact_id -> file_path."""

    @abstractmethod
    def get_profiles(self) -> dict[str, dict]:
        """Return available scan profiles for this device type."""


class AdapterRegistry:
    """Auto-discovery registry for device adapters."""

    _adapters: list[BaseAdapter] = []

    @classmethod
    def register(cls, adapter: BaseAdapter):
        cls._adapters.append(adapter)

    @classmethod
    def detect(cls, serial: str) -> BaseAdapter | None:
        """Return the first adapter that can handle this device."""
        for adapter in cls._adapters:
            if adapter.can_handle(serial):
                return adapter
        return None

    @classmethod
    def get_all(cls) -> list[BaseAdapter]:
        return list(cls._adapters)

    @classmethod
    def get_by_os(cls, os_type: str) -> BaseAdapter | None:
        for adapter in cls._adapters:
            if adapter.os_type == os_type:
                return adapter
        return None
