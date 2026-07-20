<div align="center">

# Forensic Scanner Multi-Plateforme

**A comprehensive, cross-platform digital forensic scanning framework**

[![Python](https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Multi--Platform-orange?style=for-the-badge)]()
[![Version](https://img.shields.io/badge/Version-1.0-purple?style=for-the-badge)]()

---

A modular forensic scanner that supports **9 platforms** with automated artifact collection, threat analysis, and report generation.

</div>

---

## Features

| Feature | Description |
|---------|-------------|
| **Multi-Platform** | Android, iOS, Windows, macOS, Linux, Network, Cloud, Memory, Disk |
| **Modular Architecture** | Plugin-based scanner registry with hot-swappable modules |
| **Auto-Detection** | Automatic platform and connection type detection |
| **YARA Scanning** | Rule-based malware and IOC detection |
| **Hash Analysis** | MD5/SHA1/SHA256 computation with known-bad hash matching |
| **Network Forensics** | C2 detection, suspicious port analysis, DNS forensic |
| **Malware Patterns** | Static analysis for reverse shells, injection, ransomware |
| **Report Generation** | JSON, HTML, and TXT forensic reports |
| **GUI Interface** | Modern CustomTkinter-based graphical interface |
| **CLI Support** | Command-line interface for automation |

---

## Supported Platforms

| Platform | Scanner | Capabilities |
|----------|---------|--------------|
| **Android** | `AndroidScanner` | ADB dump, log extraction, app analysis, spyware detection |
| **iOS** | `IOSScanner` | pymobiledevice3, backup analysis, keychain metadata |
| **Windows** | `WindowsScanner` | Registry, event logs, Prefetch, Amcache, browser data |
| **macOS** | `MacOSScanner` | System profiler, unified logs, LaunchAgents, SIP status |
| **Linux** | `LinuxScanner` | Syslog, auth logs, kernel modules, Docker containers |
| **Network** | `NetworkScanner` | Active connections, firewall rules, WiFi profiles |
| **Cloud** | `CloudScanner` | AWS IAM/S3/EC2, Azure RG/NSG, GCP IAM/Compute |
| **Memory** | `MemoryScanner` | Volatility plugins, process enumeration, injection detection |
| **Disk** | `DiskScanner` | Image hashing, string extraction, partition analysis |

---

## Project Structure

```
Forensic-Scanner-Multi-Plateforme/
├── main.py                    # Entry point (GUI + CLI)
├── setup.bat                  # Install dependencies (Windows)
├── run.bat                    # Launch GUI (Windows)
├── requirements.txt           # Python dependencies
│
├── core/                      # Core framework
│   ├── base_scanner.py        # Abstract scanner base class
│   ├── scanner_registry.py    # Plugin registry system
│   └── platform_detector.py   # Auto-detect target platform
│
├── scanners/                  # Platform-specific scanners
│   ├── android_scanner.py
│   ├── ios_scanner.py
│   ├── windows_scanner.py
│   ├── macos_scanner.py
│   ├── linux_scanner.py
│   ├── network_scanner.py
│   ├── cloud_scanner.py
│   ├── memory_scanner.py
│   └── disk_scanner.py
│
├── analyzers/                 # Analysis engines
│   ├── yara_analyzer.py       # YARA rule matching
│   ├── hash_analyzer.py       # Hash computation + DB lookup
│   ├── network_analyzer.py    # C2/IOC detection
│   └── malware_analyzer.py    # Malware pattern detection
│
├── collectors/                # Data collection modules
│   ├── artifact_collector.py  # Generic file collection
│   ├── log_collector.py       # System log collection
│   └── memory_collector.py    # Memory info collection
│
├── reports/                   # Report generation
│   └── report_generator.py    # JSON/HTML/TXT reports
│
├── gui/                       # Graphical interface
│   └── main_gui.py            # CustomTkinter GUI
│
└── rules/                     # Detection rules
    ├── yara/
    │   └── forensic_rules.yar
    └── iocs/
        ├── known_ips.txt
        └── hashes.txt
```

---

## Installation

### Prerequisites

- **Python 3.10+** ([Download](https://www.python.org/downloads/))
- **Git** ([Download](https://git-scm.com/))
- **ADB** (for Android scanning) ([Download](https://developer.android.com/tools/releases/platform-tools))

### Setup

```bash
# Clone the repository
git clone https://github.com/thebest1in/Forensic-Scanner-Multi-Plateforme.git
cd Forensic-Scanner-Multi-Plateforme

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Windows Quick Start

```batch
# Double-click setup.bat to install everything
setup.bat

# Double-click run.bat to launch the GUI
run.bat
```

---

## Usage

### GUI Mode

```bash
python main.py
# or
python gui/main_gui.py
```

### CLI Mode

```bash
# List available scanners
python main.py --list

# Scan a specific platform
python main.py --scan windows
python main.py --scan android SERIAL_NUMBER
python main.py --scan network
python main.py --scan cloud aws
python main.py --scan memory /path/to/dump.raw
python main.py --scan disk /path/to/image.dd

# Auto-detect platform
python main.py --scan auto /path/to/target
```

### Programmatic Usage

```python
from scanners import AndroidScanner, WindowsScanner
from core.platform_detector import PlatformDetector
from reports.report_generator import ReportGenerator
from pathlib import Path

# Auto-detect platform
info = PlatformDetector.detect()
print(f"Platform: {info.platform_type.value}")

# Run Android scan
scanner = AndroidScanner(serial="DEVICE_SERIAL")
result = scanner.scan(target="DEVICE_SERIAL", output_dir=Path("output/android"))

print(f"Verdict: {result.status.value}")
print(f"Artifacts: {result.artifact_count}")
print(f"Threats: {result.threat_count}")

# Generate reports
reporter = ReportGenerator(Path("output/android"))
reporter.generate_json_report([result.to_dict()])
reporter.generate_html_report([result.to_dict()])
```

---

## Architecture

### Core Components

| Component | Description |
|-----------|-------------|
| `BaseScanner` | Abstract base class defining the scan pipeline |
| `ScannerRegistry` | Decorator-based plugin registration system |
| `PlatformDetector` | Multi-method platform identification |
| `ScanResult` | Typed dataclass for scan outcomes |

### Scan Pipeline

```
Target → Platform Detection → Scanner Selection → Artifact Collection
    → Analysis (YARA/Hash/Network/Malware) → Threat Classification
    → Report Generation (JSON/HTML/TXT)
```

### Extending the Framework

Create a new scanner by extending `BaseScanner`:

```python
from core.base_scanner import BaseScanner
from core.scanner_registry import ScannerRegistry
from pathlib import Path

@ScannerRegistry.register
class CustomScanner(BaseScanner):
    def __init__(self, **kwargs):
        super().__init__(name="Custom Scanner", platform="custom")

    def collect_artifacts(self, target: str, output_dir: Path) -> list[dict]:
        # Collect forensic artifacts
        return [{"id": "artifact_1", "file": "path/to/file", "desc": "Description"}]

    def analyze_artifacts(self, artifacts: list[dict], output_dir: Path) -> list[dict]:
        # Analyze artifacts for threats
        return [{"type": "threat", "indicator": "malicious_pattern", "severity": "critical"}]
```

---

## Detection Rules

### YARA Rules

| Rule | Description | Severity |
|------|-------------|----------|
| `Spyware_Indicators` | Pegasus, FlexiSPY, mSpy, and 20+ spyware families | Critical |
| `Reverse_Shell` | Bash/nc/ncat/socat/Python/Perl/Ruby/PHP reverse shells | Critical |
| `Credential_Harvesting` | Mimikatz, LaZagne, LSASS dumps | Critical |
| `Ransomware_Indicators` | Encryption patterns, ransom notes, wallet addresses | Critical |
| `Process_Injection` | CreateRemoteThread, VirtualAllocEx, WriteProcessMemory | Critical |
| `Lateral_Movement` | PsExec, WMIExec, Evil-WinRM, CrackMapExec | Critical |
| `Anti_Analysis` | Debugger detection, sandbox evasion | Suspicious |

### Malware Patterns

- Reverse shells (bash, nc, ncat, socat, Python, Perl, Ruby, PHP)
- PowerShell obfuscation
- Base64-encoded execution
- Keylogger APIs
- Credential harvesting tools
- Persistence mechanisms (registry, cron, launch agents)
- Data exfiltration
- Process injection
- Privilege escalation
- Ransomware indicators

---

## Dependencies

| Package | Purpose |
|---------|---------|
| `customtkinter` | Modern GUI framework |
| `yara-python` | YARA rule scanning |
| `psutil` | Process and system utilities |
| `requests` | HTTP client for API lookups |
| `paramiko` | SSH connectivity |
| `pymobiledevice3` | iOS device communication |
| `docker` | Docker container forensics |
| `pyzipper` | Archive handling |

---

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Disclaimer

This tool is intended for **authorized forensic investigations** and **security research** only. Always ensure you have proper authorization before scanning any system or device. The authors are not responsible for misuse of this software.

---

<div align="center">

**Built for forensic professionals by forensic professionals**

[Report Bug](https://github.com/thebest1in/Forensic-Scanner-Multi-Plateforme/issues) · [Request Feature](https://github.com/thebest1in/Forensic-Scanner-Multi-Plateforme/issues)

</div>
