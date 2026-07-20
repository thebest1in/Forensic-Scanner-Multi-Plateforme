from typing import Type
from .base_scanner import BaseScanner


class ScannerRegistry:
    """Registry for managing all available forensic scanners."""

    _scanners: dict[str, Type[BaseScanner]] = {}

    @classmethod
    def register(cls, scanner_class: Type[BaseScanner]) -> Type[BaseScanner]:
        """Decorator to register a scanner class."""
        instance = scanner_class.__new__(scanner_class)
        cls._scanners[instance.name] = scanner_class
        return scanner_class

    @classmethod
    def get(cls, name: str) -> Type[BaseScanner] | None:
        return cls._scanners.get(name)

    @classmethod
    def get_all(cls) -> dict[str, Type[BaseScanner]]:
        return cls._scanners.copy()

    @classmethod
    def get_by_platform(cls, platform: str) -> dict[str, Type[BaseScanner]]:
        result = {}
        for name, scanner_cls in cls._scanners.items():
            instance = scanner_cls.__new__(scanner_cls)
            if instance.platform.lower() == platform.lower():
                result[name] = scanner_cls
        return result

    @classmethod
    def get_platforms(cls) -> list[str]:
        platforms = set()
        for scanner_cls in cls._scanners.values():
            instance = scanner_cls.__new__(scanner_cls)
            platforms.add(instance.platform)
        return sorted(platforms)

    @classmethod
    def create(cls, name: str, **kwargs) -> BaseScanner | None:
        scanner_cls = cls.get(name)
        if scanner_cls:
            return scanner_cls(**kwargs)
        return None
