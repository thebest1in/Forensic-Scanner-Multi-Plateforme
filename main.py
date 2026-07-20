import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from core.scanner_registry import ScannerRegistry
from core.platform_detector import PlatformDetector, PlatformType

import scanners  # noqa: F401 - triggers registration


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--list":
        print("Available scanners:")
        for name, cls in ScannerRegistry.get_all().items():
            instance = cls.__new__(cls)
            print(f"  - {name} ({instance.platform})")
        print(f"\nPlatforms: {', '.join(ScannerRegistry.get_platforms())}")
        return

    if len(sys.argv) > 1 and sys.argv[1] == "--scan":
        platform = sys.argv[2] if len(sys.argv) > 2 else "auto"
        target = sys.argv[3] if len(sys.argv) > 3 else ""

        if platform == "auto":
            info = PlatformDetector.detect(target)
            platform = info.platform_type.value
            print(f"Detected platform: {platform}")

        scanner = ScannerRegistry.create(platform)
        if not scanner:
            print(f"Error: No scanner found for platform '{platform}'")
            return

        print(f"Starting {scanner.name}...")
        output_dir = Path("output") / f"scan_{platform}"
        result = scanner.scan(target=target, output_dir=output_dir)
        print(f"\nScan complete:")
        print(f"  Status: {result.status.value}")
        print(f"  Artifacts: {result.artifact_count}")
        print(f"  Threats: {result.threat_count}")
        print(f"  Duration: {result.duration:.1f}s")
        return

    from gui.main_gui import ForensicScannerGUI
    app = ForensicScannerGUI()
    app.run()


if __name__ == "__main__":
    main()
