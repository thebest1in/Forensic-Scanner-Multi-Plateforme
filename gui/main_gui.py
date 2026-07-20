import sys
import time
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    import customtkinter as ctk
    CTK_AVAILABLE = True
except ImportError:
    CTK_AVAILABLE = False

from core.scanner_registry import ScannerRegistry
from core.platform_detector import PlatformDetector
from core.base_scanner import ScanStatus
from reports.report_generator import ReportGenerator

from scanners import (
    AndroidScanner, IOSScanner, WindowsScanner, MacOSScanner,
    LinuxScanner, NetworkScanner, CloudScanner, MemoryScanner, DiskScanner,
)


class ForensicScannerGUI:
    """Multi-platform forensic scanner GUI application."""

    def __init__(self):
        if not CTK_AVAILABLE:
            print("[ERROR] customtkinter not installed. Run: pip install customtkinter")
            sys.exit(1)

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.root = ctk.CTk()
        self.root.title("Forensic Scanner Multi-Plateforme v1.0")
        self.root.geometry("1000x900")
        self.root.minsize(900, 800)

        self._scan_running = False
        self._scan_results = []
        self._output_dir = Path(__file__).parent.parent / "output"
        self._output_dir.mkdir(exist_ok=True)

        self._build_ui()

    def _build_ui(self):
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_rowconfigure(6, weight=1)

        self._build_header()
        self._build_platform_panel()
        self._build_target_panel()
        self._build_options_panel()
        self._build_action_panel()
        self._build_progress_panel()
        self._build_results_panel()
        self._build_terminal_panel()

    def _build_header(self):
        frame = ctk.CTkFrame(self.root, fg_color="transparent")
        frame.grid(row=0, column=0, padx=20, pady=(15, 5), sticky="ew")
        ctk.CTkLabel(
            frame, text="Forensic Scanner Multi-Plateforme",
            font=ctk.CTkFont(size=22, weight="bold"),
        ).pack(side="left")
        ctk.CTkLabel(
            frame, text="v1.0",
            font=ctk.CTkFont(size=11), text_color="gray",
        ).pack(side="left", padx=(10, 0), pady=(5, 0))

    def _build_platform_panel(self):
        frame = ctk.CTkFrame(self.root, corner_radius=10)
        frame.grid(row=1, column=0, padx=20, pady=(10, 5), sticky="ew")

        ctk.CTkLabel(
            frame, text="Platform:", font=ctk.CTkFont(size=12, weight="bold")
        ).pack(side="left", padx=(15, 5), pady=10)

        self._platform_var = ctk.StringVar(value="auto")
        platforms = ["auto", "android", "ios", "windows", "macos", "linux", "network", "cloud", "memory", "disk"]
        self._platform_menu = ctk.CTkOptionMenu(
            frame, variable=self._platform_var, values=platforms,
            font=ctk.CTkFont(size=12), width=150,
        )
        self._platform_menu.pack(side="left", padx=5, pady=10)

        self._detect_btn = ctk.CTkButton(
            frame, text="Auto-Detect", font=ctk.CTkFont(size=11),
            width=100, height=28, command=self._auto_detect,
        )
        self._detect_btn.pack(side="left", padx=5, pady=10)

        self._platform_info = ctk.CTkLabel(
            frame, text="Select platform or auto-detect",
            font=ctk.CTkFont(size=11), text_color="gray",
        )
        self._platform_info.pack(side="left", padx=10, pady=10)

    def _auto_detect(self):
        info = PlatformDetector.detect_local()
        self._platform_var.set(info.platform_type.value)
        self._platform_info.configure(
            text=f"Detected: {info.platform_type.value} ({info.hostname})",
            text_color="#2ecc71",
        )
        self._append_terminal(f"[INFO] Platform detected: {info.platform_type.value}")

    def _build_target_panel(self):
        frame = ctk.CTkFrame(self.root, corner_radius=10)
        frame.grid(row=2, column=0, padx=20, pady=(5, 5), sticky="ew")
        frame.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            frame, text="Target:", font=ctk.CTkFont(size=12, weight="bold")
        ).grid(row=0, column=0, padx=(15, 5), pady=10)

        self._target_entry = ctk.CTkEntry(
            frame,
            placeholder_text="IP, device serial, file path, or 'ssh:user@host'",
            font=ctk.CTkFont(size=12),
        )
        self._target_entry.grid(row=0, column=1, padx=5, pady=10, sticky="ew")

        self._browse_btn = ctk.CTkButton(
            frame, text="Browse", font=ctk.CTkFont(size=11),
            width=80, height=28, command=self._browse_target,
        )
        self._browse_btn.grid(row=0, column=2, padx=(5, 15), pady=10)

    def _browse_target(self):
        from tkinter import filedialog
        path = filedialog.askdirectory(title="Select target directory")
        if path:
            self._target_entry.delete(0, "end")
            self._target_entry.insert(0, path)

    def _build_options_panel(self):
        frame = ctk.CTkFrame(self.root, corner_radius=10)
        frame.grid(row=3, column=0, padx=20, pady=(5, 5), sticky="ew")

        ctk.CTkLabel(
            frame, text="Analysis Options:", font=ctk.CTkFont(size=12, weight="bold")
        ).pack(side="left", padx=(15, 5), pady=10)

        self._yara_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(frame, text="YARA Scanning", variable=self._yara_var, font=ctk.CTkFont(size=11)).pack(side="left", padx=5, pady=10)

        self._hash_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(frame, text="Hash Check", variable=self._hash_var, font=ctk.CTkFont(size=11)).pack(side="left", padx=5, pady=10)

        self._network_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(frame, text="Network Analysis", variable=self._network_var, font=ctk.CTkFont(size=11)).pack(side="left", padx=5, pady=10)

        self._malware_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(frame, text="Malware Patterns", variable=self._malware_var, font=ctk.CTkFont(size=11)).pack(side="left", padx=5, pady=10)

    def _build_action_panel(self):
        frame = ctk.CTkFrame(self.root, fg_color="transparent")
        frame.grid(row=4, column=0, padx=20, pady=(5, 5), sticky="ew")
        frame.grid_columnconfigure(0, weight=1)

        self._scan_btn = ctk.CTkButton(
            frame, text="START SCAN", font=ctk.CTkFont(size=15, weight="bold"),
            height=45, corner_radius=8, command=self._start_scan,
        )
        self._scan_btn.grid(row=0, column=0, sticky="ew")

    def _build_progress_panel(self):
        frame = ctk.CTkFrame(self.root, corner_radius=10)
        frame.grid(row=5, column=0, padx=20, pady=(5, 5), sticky="ew")

        self._progress_bar = ctk.CTkProgressBar(frame, height=20)
        self._progress_bar.pack(padx=15, pady=(10, 5), fill="x")
        self._progress_bar.set(0)

        self._progress_label = ctk.CTkLabel(
            frame, text="Ready to scan",
            font=ctk.CTkFont(size=11), text_color="gray",
        )
        self._progress_label.pack(padx=15, pady=(0, 10), anchor="w")

    def _build_results_panel(self):
        frame = ctk.CTkFrame(self.root, corner_radius=10)
        frame.grid(row=6, column=0, padx=20, pady=(5, 5), sticky="nsew")
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(
            frame, text="Scan Results:", font=ctk.CTkFont(size=12, weight="bold")
        ).grid(row=0, column=0, padx=15, pady=(10, 5), sticky="w")

        self._results_text = ctk.CTkTextbox(
            frame, font=ctk.CTkFont(family="Consolas", size=11),
        )
        self._results_text.grid(row=1, column=0, padx=10, pady=(0, 10), sticky="nsew")

    def _build_terminal_panel(self):
        frame = ctk.CTkFrame(self.root, corner_radius=10)
        frame.grid(row=7, column=0, padx=20, pady=(5, 15), sticky="ew")
        frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            frame, text="Terminal Output:", font=ctk.CTkFont(size=12, weight="bold")
        ).grid(row=0, column=0, padx=15, pady=(10, 5), sticky="w")

        self._terminal = ctk.CTkTextbox(
            frame, font=ctk.CTkFont(family="Consolas", size=10),
            height=150,
        )
        self._terminal.grid(row=1, column=0, padx=10, pady=(0, 10), sticky="ew")

    def _append_terminal(self, message: str):
        def _do():
            self._terminal.configure(state="normal")
            self._terminal.insert("end", message + "\n")
            self._terminal.see("end")
            self._terminal.configure(state="disabled")
        self.root.after(0, _do)

    def _update_progress(self, percent: float, message: str):
        def _do():
            self._progress_bar.set(percent / 100)
            self._progress_label.configure(text=message)
        self.root.after(0, _do)

    def _start_scan(self):
        if self._scan_running:
            return

        platform = self._platform_var.get()
        target = self._target_entry.get().strip()

        if platform == "auto":
            info = PlatformDetector.detect_local()
            platform = info.platform_type.value

        self._scan_running = True
        self._scan_btn.configure(state="disabled", text="SCANNING...")
        self._results_text.configure(state="normal")
        self._results_text.delete("1.0", "end")
        self._results_text.configure(state="disabled")

        thread = threading.Thread(target=self._scan_worker, args=(platform, target), daemon=True)
        thread.start()

    def _scan_worker(self, platform: str, target: str):
        try:
            self._append_terminal(f"[INFO] Starting scan on platform: {platform}")
            self._update_progress(5, f"Initializing {platform} scanner...")

            scanner_map = {
                "android": lambda: AndroidScanner(serial=target),
                "ios": lambda: IOSScanner(serial=target),
                "windows": lambda: WindowsScanner(),
                "macos": lambda: MacOSScanner(),
                "linux": lambda: LinuxScanner(),
                "network": lambda: NetworkScanner(),
                "cloud": lambda: CloudScanner(provider=target or "aws"),
                "memory": lambda: MemoryScanner(dump_path=target),
                "disk": lambda: DiskScanner(image_path=target),
            }

            factory = scanner_map.get(platform)
            if not factory:
                self._append_terminal(f"[ERROR] Unknown platform: {platform}")
                return

            scanner = factory()
            scanner.set_progress_callback(self._update_progress)

            output_dir = self._output_dir / f"scan_{platform}_{int(time.time())}"
            result = scanner.scan(target=target or "", output_dir=output_dir)

            self._scan_results.append(result.to_dict())

            self._append_terminal(f"[OK] Scan complete: {result.scanner_name}")
            self._append_terminal(f"  Status: {result.status.value}")
            self._append_terminal(f"  Artifacts: {result.artifact_count}")
            self._append_terminal(f"  Threats: {result.threat_count}")
            self._append_terminal(f"  Duration: {result.duration:.1f}s")

            self._display_results(result.to_dict())

            report_gen = ReportGenerator(output_dir)
            json_path = report_gen.generate_json_report([result.to_dict()])
            html_path = report_gen.generate_html_report([result.to_dict()])
            txt_path = report_gen.generate_text_report([result.to_dict()])
            self._append_terminal(f"[OK] Reports saved: {output_dir}")

        except Exception as e:
            self._append_terminal(f"[ERROR] Scan failed: {e}")
        finally:
            self._scan_running = False
            self.root.after(0, self._scan_btn.configure, (), {"state": "normal", "text": "START SCAN"})
            self._update_progress(100, "Scan complete")

    def _display_results(self, result: dict):
        def _do():
            self._results_text.configure(state="normal")
            self._results_text.delete("1.0", "end")

            lines = [
                f"Scanner: {result.get('scanner_name', 'Unknown')}",
                f"Platform: {result.get('platform', 'Unknown')}",
                f"Status: {result.get('status', 'Unknown')}",
                f"Duration: {result.get('duration', 0):.1f}s",
                f"Artifacts: {result.get('artifact_count', 0)}",
                f"Threats: {result.get('threat_count', 0)}",
                "",
            ]

            threats = result.get("threats_detected", [])
            if threats:
                lines.append(f"=== THREATS ({len(threats)}) ===")
                for t in threats:
                    lines.append(f"  [{t.get('severity', '?')}] {t.get('indicator', t.get('pattern', 'unknown'))}")
                    lines.append(f"    Source: {t.get('source', 'unknown')}")
                lines.append("")

            self._results_text.insert("1.0", "\n".join(lines))
            self._results_text.configure(state="disabled")
        self.root.after(0, _do)

    def run(self):
        self.root.mainloop()


def main():
    app = ForensicScannerGUI()
    app.run()


if __name__ == "__main__":
    main()
