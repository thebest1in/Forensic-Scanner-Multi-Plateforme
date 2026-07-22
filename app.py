import subprocess
import tempfile
import threading
import time
import zipfile
from pathlib import Path
from tkinter import filedialog, messagebox

import customtkinter as ctk

from analyzer import ThreatVerdict, analyze, save_report
from core import ADB_BINARY, cleanup_dump_dir, logger
from extractor import get_profile_commands, run_extraction
from ioc_sync import sync_ioc_feeds
from recommendations_engine import PRIORITY_COLORS, generate_recommendations
from scan_lifecycle import ScanLifecycle, ScanStage, StageTimeoutError, run_with_timeout
from usb_monitor import DeviceState, USBMonitor
from version import VERSION

STATE_COLORS = {
    DeviceState.DISCONNECTED: "#e74c3c",
    DeviceState.UNAUTHORIZED: "#f39c12",
    DeviceState.READY: "#2ecc71",
}
STATE_LABELS = {
    DeviceState.DISCONNECTED: "DISCONNECTED",
    DeviceState.UNAUTHORIZED: "PLUGGED IN (LOCKED)",
    DeviceState.READY: "CONNECTED & READY",
}

STATUS_COLORS = {
    "CRITICAL": "#e74c3c",
    "SUSPICIOUS": "#f39c12",
    "CLEAN": "#2ecc71",
}

ACTION_COLORS = {
    "DELETE": "#e74c3c",
    "UPDATE": "#f39c12",
    "RESTRICT": "#3498db",
}

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class ForensicScannerApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title(f"Universal Forensic Scanner {VERSION}")
        self.geometry("960x820")
        self.minsize(860, 700)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        self._usb_monitor = USBMonitor(on_state_change=self._on_device_state)
        self._device_state = DeviceState.DISCONNECTED
        self._device_serial = None
        self._scan_running = False
        self._scan_lifecycle = ScanLifecycle()
        self._last_progress = 0.0
        self._dump_dir: Path | None = None
        self._last_result = None
        self._offline_archive: Path | None = None
        self._linux_target: str | None = None
        self._mode_var = ctk.StringVar(value="live")

        self._artifact_map: list[dict] = []
        self._filtered_artifacts: list[dict] = []
        self._remediation_actions: list[dict] = []

        self._advanced_expanded = False

        self._build_ui()
        self._usb_monitor.start()
        self._sync_ioc_feeds()

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(5, weight=1)

        self._build_header()              # Row 0: Title
        self._build_quick_buttons()       # Row 1: 3 Big Action Buttons
        self._build_conn_status()         # Row 2: Connection status
        self._build_advanced_options()    # Row 3: Collapsible Advanced
        self._build_navigator_panel()     # Row 4: Artifact Navigator
        self._build_results_panel()       # Row 5: Results Text
        self._build_findings_panel()      # Row 6: Findings Panel (hidden)
        self._build_recommendations_panel()  # Row 7: Recommendations (hidden)
        self._build_progress_panel()      # Row 8: Progress + Terminal

    # ============================================================
    # ROW 0: HEADER
    # ============================================================

    def _build_header(self):
        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.grid(row=0, column=0, padx=15, pady=(8, 2), sticky="ew")

        ctk.CTkLabel(
            frame,
            text="Universal Forensic Scanner",
            font=ctk.CTkFont(size=18, weight="bold"),
        ).pack(side="left")
        ctk.CTkLabel(
            frame,
            text=f"{VERSION} — 12-Phase Analysis + Correlation",
            font=ctk.CTkFont(size=10),
            text_color="gray",
        ).pack(side="left", padx=(8, 0), pady=(4, 0))

    # ============================================================
    # ROW 1: THREE BIG ACTION BUTTONS
    # ============================================================

    def _build_quick_buttons(self):
        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.grid(row=1, column=0, padx=15, pady=(4, 3), sticky="ew")
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_columnconfigure(1, weight=1)
        frame.grid_columnconfigure(2, weight=1)

        self._quick_pull_btn = ctk.CTkButton(
            frame,
            text="PULL & SCAN PHONE",
            font=ctk.CTkFont(size=13, weight="bold"),
            height=42,
            corner_radius=8,
            fg_color="#2980b9",
            hover_color="#2471a3",
            command=self._quick_pull_scan,
        )
        self._quick_pull_btn.grid(row=0, column=0, padx=(0, 4), sticky="ew", ipady=2)

        self._quick_archive_btn = ctk.CTkButton(
            frame,
            text="SCAN ARCHIVE",
            font=ctk.CTkFont(size=13, weight="bold"),
            height=42,
            corner_radius=8,
            fg_color="#8e44ad",
            hover_color="#7d3c98",
            command=self._quick_scan_archive,
        )
        self._quick_archive_btn.grid(row=0, column=1, padx=4, sticky="ew", ipady=2)

        self._quick_live_btn = ctk.CTkButton(
            frame,
            text="SCAN LIVE",
            font=ctk.CTkFont(size=13, weight="bold"),
            height=42,
            corner_radius=8,
            fg_color="#27ae60",
            hover_color="#219a52",
            command=self._quick_scan_live,
        )
        self._quick_live_btn.grid(row=0, column=2, padx=(4, 0), sticky="ew", ipady=2)

    # ============================================================
    # ROW 2: CONNECTION STATUS (SIMPLIFIED)
    # ============================================================

    def _build_conn_status(self):
        frame = ctk.CTkFrame(self, corner_radius=10)
        frame.grid(row=2, column=0, padx=15, pady=(0, 3), sticky="ew")
        frame.grid_columnconfigure(2, weight=1)

        self._status_dot = ctk.CTkLabel(frame, text="\u25cf", font=ctk.CTkFont(size=22))
        self._status_dot.configure(text_color=STATE_COLORS[DeviceState.DISCONNECTED])
        self._status_dot.grid(row=0, column=0, padx=(10, 5), pady=6)

        info_frame = ctk.CTkFrame(frame, fg_color="transparent")
        info_frame.grid(row=0, column=1, padx=2, pady=6, sticky="w")
        self._status_label = ctk.CTkLabel(
            info_frame, text=STATE_LABELS[DeviceState.DISCONNECTED],
            font=ctk.CTkFont(size=11, weight="bold"),
        )
        self._status_label.pack(anchor="w")
        self._serial_label = ctk.CTkLabel(
            info_frame, text="No device",
            font=ctk.CTkFont(size=9), text_color="gray",
        )
        self._serial_label.pack(anchor="w")

        sep = ctk.CTkFrame(frame, width=1, height=30, fg_color="gray50")
        sep.grid(row=0, column=2, padx=6, pady=6)

        self._case_label = ctk.CTkLabel(
            frame, text="Case:", font=ctk.CTkFont(size=10, weight="bold"),
        )
        self._case_label.grid(row=0, column=3, padx=(4, 2), pady=6, sticky="w")
        self._case_entry = ctk.CTkEntry(
            frame, placeholder_text="CASE-2026-001",
            font=ctk.CTkFont(size=10), width=130,
        )
        self._case_entry.grid(row=0, column=4, padx=(0, 8), pady=6, sticky="w")

        sep2 = ctk.CTkFrame(frame, width=1, height=30, fg_color="gray50")
        sep2.grid(row=0, column=5, padx=6, pady=6)

        self._case_history_btn = ctk.CTkButton(
            frame, text="History", font=ctk.CTkFont(size=9),
            width=55, height=24, command=self._show_scan_history,
        )
        self._case_history_btn.grid(row=0, column=6, padx=(0, 10), pady=6)

    # ============================================================
    # ROW 3: COLLAPSIBLE ADVANCED OPTIONS
    # ============================================================

    def _build_advanced_options(self):
        self._adv_outer = ctk.CTkFrame(self, fg_color="transparent")
        self._adv_outer.grid(row=3, column=0, padx=15, pady=(0, 3), sticky="ew")
        self._adv_outer.grid_columnconfigure(0, weight=1)

        self._adv_toggle_btn = ctk.CTkButton(
            self._adv_outer,
            text="Show Advanced Options \u25B6",
            font=ctk.CTkFont(size=11, weight="bold"),
            height=28,
            corner_radius=6,
            fg_color="#34495e",
            hover_color="#2c3e50",
            command=self._toggle_advanced,
        )
        self._adv_toggle_btn.grid(row=0, column=0, sticky="ew")

        self._adv_content = ctk.CTkFrame(self._adv_outer, fg_color="transparent")
        self._adv_content.grid(row=1, column=0, sticky="ew")
        self._adv_content.grid_columnconfigure(0, weight=1)
        self._adv_content.grid_columnconfigure(1, weight=1)
        self._adv_content.grid_columnconfigure(2, weight=1)

        # --- Profile radios (top of advanced) ---
        profile_frame = ctk.CTkFrame(self._adv_content, fg_color="#1a1a2e", corner_radius=6)
        profile_frame.grid(row=0, column=0, columnspan=3, pady=(2, 3), sticky="ew", padx=2)
        ctk.CTkLabel(
            profile_frame, text="PROFILE",
            font=ctk.CTkFont(size=9, weight="bold"), text_color="#1abc9c",
        ).pack(side="left", padx=6, pady=(3, 3))

        self._profile_var = ctk.StringVar(value="deep")
        ctk.CTkRadioButton(
            profile_frame, text="Triage (4 artifacts)",
            variable=self._profile_var, value="triage",
            font=ctk.CTkFont(size=10),
        ).pack(side="left", padx=6)
        ctk.CTkRadioButton(
            profile_frame, text="Deep (18 artifacts)",
            variable=self._profile_var, value="deep",
            font=ctk.CTkFont(size=10),
        ).pack(side="left", padx=6)

        # --- Device Type radios ---
        dt_sep = ctk.CTkFrame(profile_frame, width=1, height=24, fg_color="gray50")
        dt_sep.pack(side="left", padx=8, pady=4)
        ctk.CTkLabel(
            profile_frame, text="Device:", font=ctk.CTkFont(size=10, weight="bold"),
        ).pack(side="left", padx=(4, 2))
        self._device_type_var = ctk.StringVar(value="android")
        for val, label in [("android", "Android"), ("ios", "iOS"), ("linux", "Linux")]:
            ctk.CTkRadioButton(
                profile_frame, text=label, variable=self._device_type_var, value=val,
                font=ctk.CTkFont(size=10), command=self._on_device_type_change,
            ).pack(side="left", padx=3)

        # Linux target entry (hidden by default)
        self._linux_input_frame = ctk.CTkFrame(profile_frame, fg_color="transparent")
        self._linux_input_frame.pack(side="left", padx=(6, 0))
        self._linux_target_entry = ctk.CTkEntry(
            self._linux_input_frame, placeholder_text="ssh:user@host",
            font=ctk.CTkFont(size=9), width=160,
        )
        self._linux_target_entry.pack(side="left")
        self._linux_target_entry.configure(state="disabled")
        self._linux_connect_btn = ctk.CTkButton(
            self._linux_input_frame, text="Go", font=ctk.CTkFont(size=9),
            width=40, height=24, state="disabled",
            command=self._connect_linux_target,
        )
        self._linux_connect_btn.pack(side="left", padx=(2, 0))

        # --- ACQUISITION column ---
        acq_frame = ctk.CTkFrame(self._adv_content, fg_color="#1a1a2e", corner_radius=6)
        acq_frame.grid(row=1, column=0, padx=(0, 3), pady=1, sticky="ew")
        ctk.CTkLabel(
            acq_frame, text="ACQUISITION",
            font=ctk.CTkFont(size=9, weight="bold"), text_color="#3498db",
        ).pack(anchor="w", padx=6, pady=(3, 0))

        self._pcap_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            acq_frame, text="Live PCAP",
            variable=self._pcap_var, font=ctk.CTkFont(size=10),
        ).pack(anchor="w", padx=6, pady=1)
        self._vt_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            acq_frame, text="VirusTotal IP",
            variable=self._vt_var, font=ctk.CTkFont(size=10),
        ).pack(anchor="w", padx=6, pady=1)
        self._save_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(
            acq_frame, text="JSON Report",
            variable=self._save_var, font=ctk.CTkFont(size=10),
        ).pack(anchor="w", padx=6, pady=1)
        self._timeline_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(
            acq_frame, text="Timeline CSV",
            variable=self._timeline_var, font=ctk.CTkFont(size=10),
        ).pack(anchor="w", padx=6, pady=(1, 3))

        # --- ANALYSIS column ---
        analysis_frame = ctk.CTkFrame(self._adv_content, fg_color="#1a1a2e", corner_radius=6)
        analysis_frame.grid(row=1, column=1, padx=3, pady=1, sticky="ew")
        ctk.CTkLabel(
            analysis_frame, text="ANALYSIS",
            font=ctk.CTkFont(size=9, weight="bold"), text_color="#e67e22",
        ).pack(anchor="w", padx=6, pady=(3, 0))

        self._mvt_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            analysis_frame, text="MVT Spyware",
            variable=self._mvt_var, font=ctk.CTkFont(size=10),
        ).pack(anchor="w", padx=6, pady=1)
        self._aleapp_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            analysis_frame, text="ALEAPP Artifacts",
            variable=self._aleapp_var, font=ctk.CTkFont(size=10),
        ).pack(anchor="w", padx=6, pady=1)
        self._capa_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            analysis_frame, text="Capa Capabilities",
            variable=self._capa_var, font=ctk.CTkFont(size=10),
        ).pack(anchor="w", padx=6, pady=1)
        self._apkid_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            analysis_frame, text="APKiD Packers",
            variable=self._apkid_var, font=ctk.CTkFont(size=10),
        ).pack(anchor="w", padx=6, pady=1)
        self._quark_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            analysis_frame, text="Quark Behavioral",
            variable=self._quark_var, font=ctk.CTkFont(size=10),
        ).pack(anchor="w", padx=6, pady=1)
        self._entropy_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            analysis_frame, text="Entropy Exfil",
            variable=self._entropy_var, font=ctk.CTkFont(size=10),
        ).pack(anchor="w", padx=6, pady=1)
        self._browser_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            analysis_frame, text="Browser Forensics",
            variable=self._browser_var, font=ctk.CTkFont(size=10),
        ).pack(anchor="w", padx=6, pady=(1, 3))

        # --- INTEL + ACTION column ---
        intel_frame = ctk.CTkFrame(self._adv_content, fg_color="#1a1a2e", corner_radius=6)
        intel_frame.grid(row=1, column=2, padx=(3, 0), pady=1, sticky="ew")
        ctk.CTkLabel(
            intel_frame, text="INTEL + ACTION",
            font=ctk.CTkFont(size=9, weight="bold"), text_color="#e74c3c",
        ).pack(anchor="w", padx=6, pady=(3, 0))

        self._intel_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            intel_frame, text="OTX Live IP",
            variable=self._intel_var, font=ctk.CTkFont(size=10),
        ).pack(anchor="w", padx=6, pady=1)
        self._encrypt_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            intel_frame, text="Encrypt CRITICAL",
            variable=self._encrypt_var, font=ctk.CTkFont(size=10),
        ).pack(anchor="w", padx=6, pady=1)
        self._correlation_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(
            intel_frame, text="Cross-Tool Correlation",
            variable=self._correlation_var, font=ctk.CTkFont(size=10),
        ).pack(anchor="w", padx=6, pady=(1, 3))

        # Hide advanced content by default
        self._adv_content.grid_remove()

    def _toggle_advanced(self):
        if self._advanced_expanded:
            self._adv_content.grid_remove()
            self._adv_toggle_btn.configure(text="Show Advanced Options \u25B6")
            self._advanced_expanded = False
        else:
            self._adv_content.grid()
            self._adv_toggle_btn.configure(text="Hide Advanced Options \u25BC")
            self._advanced_expanded = True

    # ============================================================
    # DEVICE TYPE / LINUX HANDLING
    # ============================================================

    def _on_device_type_change(self):
        dt = self._device_type_var.get()
        if dt == "linux":
            self._linux_target_entry.configure(state="normal")
            self._linux_connect_btn.configure(state="normal")
        else:
            self._linux_target_entry.configure(state="disabled")
            self._linux_connect_btn.configure(state="disabled")
            self._linux_target = None

    def _connect_linux_target(self):
        target = self._linux_target_entry.get().strip()
        if not target:
            return
        self._linux_target = target
        self._device_serial = target
        self._device_state = DeviceState.READY
        self._serial_label.configure(text=f"Target: {target}")
        self._append_terminal(f"[OK] Linux target set: {target}")

    # ============================================================
    # ROW 4: ARTIFACT NAVIGATOR
    # ============================================================

    def _build_navigator_panel(self):
        self._nav_frame = ctk.CTkFrame(self, corner_radius=10)
        self._nav_frame.grid(row=4, column=0, padx=15, pady=(0, 3), sticky="ew")
        self._nav_frame.grid_columnconfigure(2, weight=1)

        self._nav_count_label = ctk.CTkLabel(
            self._nav_frame,
            text="ARTIFACT NAVIGATOR: No artifacts loaded",
            font=ctk.CTkFont(size=10, weight="bold"),
        )
        self._nav_count_label.grid(row=0, column=0, columnspan=5, padx=10, pady=(4, 1), sticky="w")

        ctk.CTkLabel(
            self._nav_frame, text="Filter:", font=ctk.CTkFont(size=10)
        ).grid(row=1, column=0, padx=(10, 2), pady=(1, 4))

        self._nav_filter_var = ctk.StringVar(value="ALL")
        self._nav_filter_menu = ctk.CTkOptionMenu(
            self._nav_frame, variable=self._nav_filter_var,
            values=["ALL", "CRITICAL", "SUSPICIOUS", "CLEAN"],
            font=ctk.CTkFont(size=10), width=100,
            command=self._on_nav_filter_change,
        )
        self._nav_filter_menu.grid(row=1, column=1, padx=2, pady=(1, 4))

        self._nav_search = ctk.CTkEntry(
            self._nav_frame, placeholder_text="Search files...",
            font=ctk.CTkFont(size=10), width=150,
        )
        self._nav_search.grid(row=1, column=2, padx=2, pady=(1, 4), sticky="ew")
        self._nav_search.bind("<KeyRelease>", self._on_nav_search_change)

        self._nav_file_var = ctk.StringVar(value="")
        self._nav_file_menu = ctk.CTkComboBox(
            self._nav_frame, variable=self._nav_file_var,
            values=["No artifacts loaded"],
            font=ctk.CTkFont(size=10), width=240,
            command=self._on_nav_file_select,
        )
        self._nav_file_menu.grid(row=1, column=3, padx=2, pady=(1, 4))

        self._nav_inspect_btn = ctk.CTkButton(
            self._nav_frame, text="Inspect", font=ctk.CTkFont(size=10),
            width=60, height=24, state="disabled",
            command=self._open_inspect_window,
        )
        self._nav_inspect_btn.grid(row=1, column=4, padx=(2, 10), pady=(1, 4))

    def _update_navigator(self):
        artifacts = self._artifact_map
        filt = self._nav_filter_var.get()
        if filt != "ALL":
            artifacts = [a for a in artifacts if a.get("status") == filt]
        search = self._nav_search.get().strip().lower()
        if search:
            artifacts = [a for a in artifacts if search in a["name"].lower()]

        self._filtered_artifacts = artifacts

        total = len(self._artifact_map)
        shown = len(artifacts)
        crit = sum(1 for a in self._artifact_map if a["status"] == "CRITICAL")
        sus = sum(1 for a in self._artifact_map if a["status"] == "SUSPICIOUS")
        scanned = getattr(self._last_result, "scanned_files", 0) if self._last_result else 0
        label = f"ARTIFACT NAVIGATOR: {shown}/{total} indexed"
        if scanned and scanned != total:
            label += f" \u00b7 {scanned} scanned"
        if total > 0:
            label += f"  |  CRITICAL: {crit}  SUSPICIOUS: {sus}"
        self._nav_count_label.configure(text=label)

        display_names = []
        for a in artifacts:
            icon = {"CRITICAL": "[!]", "SUSPICIOUS": "[~]", "CLEAN": "[ok]"}.get(a["status"], "")
            display_names.append(f"{icon} {a['name']} ({a['size_human']})")

        if not display_names:
            display_names = ["No matching files"]

        self._nav_file_menu.configure(values=display_names)
        if display_names and display_names[0] != "No matching files":
            self._nav_file_var.set(display_names[0])
            self._nav_inspect_btn.configure(state="normal")
        else:
            self._nav_file_var.set("")
            self._nav_inspect_btn.configure(state="disabled")

    def _on_nav_filter_change(self, _=None):
        self._update_navigator()

    def _on_nav_search_change(self, _=None):
        self._update_navigator()

    def _on_nav_file_select(self, _=None):
        if self._filtered_artifacts:
            self._nav_inspect_btn.configure(state="normal")

    def _clear_navigator(self):
        self._artifact_map = []
        self._filtered_artifacts = []
        if hasattr(self, "_nav_count_label"):
            self._nav_count_label.configure(text="ARTIFACT NAVIGATOR: No artifacts loaded")
            self._nav_file_menu.configure(values=["No artifacts loaded"])
            self._nav_file_var.set("")
            self._nav_inspect_btn.configure(state="disabled")
            self._nav_filter_var.set("ALL")
            self._nav_search.delete(0, "end")

    def _update_navigator_status(self, result):
        matched_files = {m.get("file", "") for m in result.matched_rules}
        for artifact in self._artifact_map:
            if artifact["name"] in matched_files:
                crit_rules = [m for m in result.matched_rules
                              if m.get("file") == artifact["name"]
                              and any(t in ("pegasus", "novispy", "finspy", "dendroid",
                                            "hackingteam", "sandrorat", "reverse_shell")
                                      for t in m.get("tags", []))]
                if crit_rules:
                    artifact["status"] = "CRITICAL"
                else:
                    artifact["status"] = "SUSPICIOUS"
        self.after(0, self._update_navigator)

    # ============================================================
    # INSPECT SUB-VIEWER
    # ============================================================

    def _open_inspect_window(self):
        idx = self._nav_file_menu.current()
        if idx < 0 or idx >= len(self._filtered_artifacts):
            return

        artifact = self._filtered_artifacts[idx]
        file_path = Path(artifact["path"])

        if not file_path.exists():
            return

        win = ctk.CTkToplevel(self)
        win.title(f"Inspect: {artifact['name']}")
        win.geometry("800x600")
        win.grid_columnconfigure(0, weight=1)
        win.grid_rowconfigure(1, weight=1)

        hdr = ctk.CTkFrame(win, fg_color="transparent")
        hdr.grid(row=0, column=0, padx=10, pady=(10, 5), sticky="ew")

        status = artifact.get("status", "CLEAN")
        color = STATUS_COLORS.get(status, "gray")

        ctk.CTkLabel(
            hdr, text=f"{artifact['name']}",
            font=ctk.CTkFont(size=14, weight="bold"),
        ).pack(side="left")

        ctk.CTkLabel(
            hdr, text=f"  [{status}]",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=color,
        ).pack(side="left")

        ctk.CTkLabel(
            hdr, text=f"  {artifact['size_human']}",
            font=ctk.CTkFont(size=11), text_color="gray",
        ).pack(side="left")

        ctk.CTkButton(
            hdr, text="Copy Path", font=ctk.CTkFont(size=10),
            width=80, height=24,
            command=lambda: self._copy_to_clipboard(artifact["path"]),
        ).pack(side="right")

        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            content = "<binary file — cannot display>"

        if len(content) > 100000:
            content = content[:100000] + f"\n\n... [truncated — {len(content)} chars total]"

        textbox = ctk.CTkTextbox(
            win, font=ctk.CTkFont(family="Consolas", size=11),
        )
        textbox.grid(row=1, column=0, padx=10, pady=(0, 10), sticky="nsew")

        textbox.configure(state="normal")
        textbox.insert("1.0", content)

        self._highlight_keywords(textbox, content)

        textbox.configure(state="disabled")

    def _highlight_keywords(self, textbox, content: str):
        highlight_terms = [
            ("flexispy", "#e74c3c"), ("mspy", "#e74c3c"),
            ("pegasus", "#e74c3c"), ("dendroid", "#e74c3c"),
            ("sandrorat", "#e74c3c"), ("hackingteam", "#e74c3c"),
            ("finspy", "#e74c3c"), ("novispy", "#e74c3c"),
            ("droidjack", "#e74c3c"),
            ("reverse shell", "#e74c3c"), ("4444", "#f39c12"),
            ("SYSTEM_ALERT_WINDOW", "#f39c12"),
            ("RECORD_AUDIO", "#f39c12"), ("READ_SMS", "#f39c12"),
            ("SEND_SMS", "#f39c12"), ("BIND_ACCESSIBILITY", "#f39c12"),
            ("BIND_DEVICE_ADMIN", "#f39c12"),
        ]

        content_lower = content.lower()
        for term, color in highlight_terms:
            term_lower = term.lower()
            start = 0
            while True:
                idx = content_lower.find(term_lower, start)
                if idx == -1:
                    break
                end_idx = idx + len(term)
                tag_name = f"hl_{term.replace(' ', '_')}_{idx}"
                textbox.tag_add(tag_name, f"1.0+{idx}c", f"1.0+{end_idx}c")
                textbox.tag_config(
                    tag_name, foreground=color,
                    font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
                )
                start = end_idx

    def _copy_to_clipboard(self, text: str):
        self.clipboard_clear()
        self.clipboard_append(text)
        self._append_terminal(f"[OK] Copied to clipboard: {text[:60]}...")

    # ============================================================
    # ROW 5: RESULTS TEXT
    # ============================================================

    def _build_results_panel(self):
        self._results_frame = ctk.CTkFrame(self, corner_radius=10)
        self._results_frame.grid(row=5, column=0, padx=15, pady=(0, 3), sticky="nsew")
        self._results_frame.grid_columnconfigure(0, weight=1)
        self._results_frame.grid_rowconfigure(0, weight=1)

        self._results_text = ctk.CTkTextbox(
            self._results_frame,
            font=ctk.CTkFont(family="Consolas", size=11),
            state="disabled", wrap="word",
        )
        self._results_text.grid(row=0, column=0, padx=8, pady=8, sticky="nsew")

    def _show_results(self, result):
        verdict = result.verdict
        if verdict == ThreatVerdict.CRITICAL:
            color = "#e74c3c"
        elif verdict == ThreatVerdict.SUSPICIOUS:
            color = "#f39c12"
        else:
            color = "#2ecc71"  # noqa: F841

        summary = result.summary

        composite_score = getattr(result, "composite_risk_score", None)
        if composite_score is not None:
            summary += (
                f"\n\n--- Risk Assessment ---"
                f"\nWeighted Risk Score: {composite_score}/100"
                f" ({getattr(result, 'composite_risk_level', 'UNKNOWN')})"
                f"\nAuthoritative Verdict: {result.verdict}"
            )
            for reason in getattr(result, "verdict_reasons", []):
                summary += f"\n  - {reason}"
            tool_status = getattr(result, "tool_status", {})
            failed = [k for k, v in tool_status.items() if v in ("error", "unavailable")]
            if failed:
                summary += f"\nTools not run: {', '.join(failed)}"
        if result.heuristic_result:
            hr = result.heuristic_result
            summary += (
                f"\nPermission Score: {hr.get('risk_score', 0)}/100"
                f" ({hr.get('risk_level', 'UNKNOWN')})"
            )

        remed = getattr(result, "_remediation", None)
        if remed and remed.get("actions"):
            summary += f"\n\n--- Remediation Actions ({remed['total_actions']}) ---"
            for act in remed["actions"]:
                icon = {"DELETE": "[DELETE]", "UPDATE": "[UPDATE]", "RESTRICT": "[RESTRICT]"}.get(act["action"], "")
                summary += f"\n{icon} {act['target']} — {act['reason']}"
                if act.get("adb_command"):
                    summary += f"\n    > {act['adb_command']}"

        if result.pcap_results and result.pcap_results.get("c2_hits"):
            summary += "\n\n--- PCAP C2 Hits ---"
            for hit in result.pcap_results["c2_hits"][:10]:
                summary += f"\n  {hit.get('domain', '?')} ({hit.get('category', '?')})"

        if result.history_delta and result.history_delta.get("anomalies"):
            summary += "\n\n--- Delta Anomalies ---"
            for a in result.history_delta["anomalies"]:
                summary += f"\n  {a}"

        self._results_text.configure(state="normal")
        self._results_text.delete("1.0", "end")
        self._results_text.insert("1.0", summary)
        self._results_text.configure(state="disabled")

        # Show findings panel if threats found
        self._show_findings(result)

        # Generate and show recommendations
        self._generate_and_show_recommendations(result)

    # ============================================================
    # ROW 6: FINDINGS PANEL (REMOVABLE APPS)
    # ============================================================

    def _build_findings_panel(self):
        self._findings_outer = ctk.CTkFrame(self, corner_radius=10)
        self._findings_outer.grid(row=6, column=0, padx=15, pady=(0, 3), sticky="ew")
        self._findings_outer.grid_columnconfigure(0, weight=1)
        self._findings_outer.grid_remove()

        header = ctk.CTkFrame(self._findings_outer, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=6, pady=(4, 0))
        ctk.CTkLabel(
            header, text="REMOVABLE FINDINGS",
            font=ctk.CTkFont(size=11, weight="bold"), text_color="#e74c3c",
        ).pack(side="left")
        ctk.CTkLabel(
            header, text="\u2014 packages that can be uninstalled via ADB",
            font=ctk.CTkFont(size=9), text_color="gray",
        ).pack(side="left", padx=(4, 0))

        self._findings_scroll = ctk.CTkScrollableFrame(
            self._findings_outer, height=120,
        )
        self._findings_scroll.grid(row=1, column=0, padx=6, pady=(2, 6), sticky="ew")
        self._findings_scroll.grid_columnconfigure(0, weight=1)

        self._findings_cards: list[ctk.CTkFrame] = []

    def _clear_findings(self):
        for card in self._findings_cards:
            card.destroy()
        self._findings_cards.clear()
        self._findings_outer.grid_remove()

    def _show_findings(self, result):
        self._clear_findings()

        removable = []

        # Collect packages from remediation DELETE actions
        remed = getattr(result, "_remediation", None)
        if remed and remed.get("actions"):
            for act in remed["actions"]:
                if act.get("action") == "DELETE" and act.get("target_type") == "package":
                    pkg = act.get("target", "")
                    if pkg:
                        removable.append({
                            "package": pkg,
                            "reason": act.get("reason", "Flagged by analysis"),
                            "severity": act.get("severity", "HIGH"),
                            "adb_command": act.get("adb_command", f"adb uninstall {pkg}"),
                        })

        # Also collect from heuristic_result suspicious_packages
        hr = getattr(result, "heuristic_result", None) or {}
        if isinstance(hr, dict):
            for pkg_name in hr.get("suspicious_packages", []):
                if isinstance(pkg_name, str) and pkg_name not in [r["package"] for r in removable]:
                    removable.append({
                        "package": pkg_name,
                        "reason": "Suspicious permission pattern detected",
                        "severity": "HIGH",
                        "adb_command": f"adb uninstall {pkg_name}",
                    })

        if not removable:
            return

        row_idx = 0
        for item in removable:
            card = ctk.CTkFrame(self._findings_scroll, fg_color="#1a1a2e", corner_radius=6)
            card.grid(row=row_idx, column=0, sticky="ew", padx=2, pady=2)
            card.grid_columnconfigure(1, weight=1)

            # Severity badge
            sev = item.get("severity", "HIGH")
            badge_color = "#e74c3c" if sev == "CRITICAL" else "#f39c12"
            badge = ctk.CTkLabel(
                card, text=f" {sev} ",
                font=ctk.CTkFont(size=9, weight="bold"),
                fg_color=badge_color, corner_radius=4, text_color="white",
            )
            badge.grid(row=0, column=0, rowspan=2, padx=(8, 4), pady=6)

            # Package name + reason
            info = ctk.CTkFrame(card, fg_color="transparent")
            info.grid(row=0, column=1, sticky="ew", pady=(4, 0))
            ctk.CTkLabel(
                info, text=item["package"],
                font=ctk.CTkFont(size=11, weight="bold"),
                anchor="w",
            ).pack(anchor="w")
            ctk.CTkLabel(
                info, text=item["reason"][:100],
                font=ctk.CTkFont(size=9), text_color="gray",
                anchor="w",
            ).pack(anchor="w")

            # Remove button
            remove_btn = ctk.CTkButton(
                card, text="Remove",
                font=ctk.CTkFont(size=10, weight="bold"),
                width=70, height=26,
                fg_color="#c0392b", hover_color="#96281b",
                command=lambda pkg=item["package"], btn=None: self._remove_package(pkg, btn),
            )
            remove_btn.grid(row=0, column=2, rowspan=2, padx=(4, 8), pady=6)
            # Store button reference on card for later disabling
            card._remove_btn = remove_btn

            self._findings_cards.append(card)
            row_idx += 1

        self._findings_outer.grid()

    def _remove_package(self, package_name, button):
        if self._device_state != DeviceState.READY:
            messagebox.showwarning(
                "No Device",
                "Connect a device via USB to remove packages.",
            )
            return

        confirm = messagebox.askyesno(
            "Confirm Removal",
            f"Uninstall package for current user?\n\n{package_name}\n\n"
            "This will run:\nadb shell pm uninstall --user 0 <package>",
        )
        if not confirm:
            return

        self._append_terminal(f"[INFO] Removing package: {package_name}")

        def _worker():
            serial = self._device_serial or ""
            cmd = [ADB_BINARY]
            if serial:
                cmd += ["-s", serial]
            cmd += ["shell", "pm", "uninstall", "--user", "0", package_name]

            try:
                proc = subprocess.run(
                    cmd, capture_output=True, text=True,
                    encoding="utf-8", errors="replace", timeout=30,
                )
                output = proc.stdout.strip()
                if "Success" in output:
                    self.after(0, self._append_terminal,
                               f"[OK] Uninstalled: {package_name}")
                    self.after(0, self._disable_remove_button, package_name)
                else:
                    err = proc.stderr.strip() or output
                    self.after(0, self._append_terminal,
                               f"[ERROR] Failed to uninstall {package_name}: {err}")
            except subprocess.TimeoutExpired:
                self.after(0, self._append_terminal,
                           f"[ERROR] Uninstall timed out: {package_name}")
            except Exception as e:
                self.after(0, self._append_terminal,
                           f"[ERROR] Uninstall failed: {e}")

        threading.Thread(target=_worker, daemon=True).start()

    def _disable_remove_button(self, package_name):
        for card in self._findings_cards:
            if hasattr(card, "_remove_btn"):
                btn = card._remove_btn
                try:
                    btn.configure(state="disabled", text="Removed",
                                  fg_color="#555555")
                except Exception:
                    pass

    # ============================================================
    # ROW 7: RECOMMENDATIONS PANEL
    # ============================================================

    def _build_recommendations_panel(self):
        self._recs_outer = ctk.CTkFrame(self, corner_radius=10)
        self._recs_outer.grid(row=7, column=0, padx=15, pady=(0, 3), sticky="ew")
        self._recs_outer.grid_columnconfigure(0, weight=1)
        self._recs_outer.grid_remove()

        header = ctk.CTkFrame(self._recs_outer, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=6, pady=(4, 0))
        ctk.CTkLabel(
            header, text="RECOMMENDATIONS",
            font=ctk.CTkFont(size=11, weight="bold"), text_color="#3498db",
        ).pack(side="left")
        ctk.CTkLabel(
            header, text="\u2014 prioritized security actions",
            font=ctk.CTkFont(size=9), text_color="gray",
        ).pack(side="left", padx=(4, 0))

        self._recs_scroll = ctk.CTkScrollableFrame(
            self._recs_outer, height=150,
        )
        self._recs_scroll.grid(row=1, column=0, padx=6, pady=(2, 6), sticky="ew")
        self._recs_scroll.grid_columnconfigure(0, weight=1)

        self._recs_cards: list[ctk.CTkFrame] = []

    def _clear_recommendations(self):
        for card in self._recs_cards:
            card.destroy()
        self._recs_cards.clear()
        self._recs_outer.grid_remove()

    def _show_recommendations(self, recommendations_result):
        self._clear_recommendations()

        if not recommendations_result or not recommendations_result.recommendations:
            return

        row_idx = 0
        for rec in recommendations_result.recommendations:
            priority = rec.get("priority", "LOW")
            rec_type = rec.get("type", "INFORMATIONAL")
            target_name = rec.get("target_name", rec.get("target", "Unknown"))
            reason = rec.get("reason", "")
            adb_command = rec.get("adb_command")

            card = ctk.CTkFrame(self._recs_scroll, fg_color="#1a1a2e", corner_radius=6)
            card.grid(row=row_idx, column=0, sticky="ew", padx=2, pady=2)
            card.grid_columnconfigure(1, weight=1)

            priority_color = PRIORITY_COLORS.get(priority, "#3498db")
            badge = ctk.CTkLabel(
                card, text=f" {priority} ",
                font=ctk.CTkFont(size=9, weight="bold"),
                fg_color=priority_color, corner_radius=4, text_color="white",
            )
            badge.grid(row=0, column=0, rowspan=2, padx=(8, 4), pady=6)

            info = ctk.CTkFrame(card, fg_color="transparent")
            info.grid(row=0, column=1, sticky="ew", pady=(4, 0))
            ctk.CTkLabel(
                info, text=f"[{rec_type}] {target_name}",
                font=ctk.CTkFont(size=11, weight="bold"),
                anchor="w",
            ).pack(anchor="w")
            ctk.CTkLabel(
                info, text=reason[:120],
                font=ctk.CTkFont(size=9), text_color="gray",
                anchor="w",
            ).pack(anchor="w")

            if adb_command:
                action_btn = ctk.CTkButton(
                    card, text="Execute",
                    font=ctk.CTkFont(size=10, weight="bold"),
                    width=70, height=26,
                    fg_color="#27ae60", hover_color="#1e8449",
                    command=lambda cmd=adb_command, tgt=target_name: self._execute_recommendation(cmd, tgt),
                )
                action_btn.grid(row=0, column=2, rowspan=2, padx=(4, 8), pady=6)
            elif rec_type == "MANUAL_REVIEW":
                ctk.CTkLabel(
                    card, text="Review",
                    font=ctk.CTkFont(size=9), text_color="gray",
                ).grid(row=0, column=2, rowspan=2, padx=(4, 8), pady=6)

            self._recs_cards.append(card)
            row_idx += 1

        self._recs_outer.grid()

    def _execute_recommendation(self, command, target_name):
        if self._device_state != DeviceState.READY:
            messagebox.showwarning(
                "No Device",
                "Connect a device via USB to execute recommendations.",
            )
            return

        confirm = messagebox.askyesno(
            "Confirm Action",
            f"Execute recommendation for {target_name}?\n\n{command}",
        )
        if not confirm:
            return

        self._append_terminal(f"[INFO] Executing recommendation: {command}")

        def _worker():
            serial = self._device_serial or ""
            cmd_parts = command.split()
            if serial and len(cmd_parts) > 1:
                cmd_parts.insert(1, "-s")
                cmd_parts.insert(2, serial)

            try:
                proc = subprocess.run(
                    cmd_parts, capture_output=True, text=True,
                    encoding="utf-8", errors="replace", timeout=30,
                )
                output = proc.stdout.strip()
                if proc.returncode == 0:
                    self.after(0, self._append_terminal,
                               f"[OK] Recommendation executed: {target_name}")
                else:
                    err = proc.stderr.strip() or output
                    self.after(0, self._append_terminal,
                               f"[ERROR] Failed: {target_name}: {err}")
            except subprocess.TimeoutExpired:
                self.after(0, self._append_terminal,
                           f"[ERROR] Timeout: {target_name}")
            except Exception as e:
                self.after(0, self._append_terminal,
                           f"[ERROR] Failed: {e}")

        threading.Thread(target=_worker, daemon=True).start()

    def _generate_and_show_recommendations(self, result):
        """Generate recommendations from scan results and display them."""
        try:
            remediation_result = None
            remed = getattr(result, "_remediation", None)
            if remed:
                from remediation_engine import RemediationResult
                remediation_result = RemediationResult()
                remediation_result.actions = remed.get("actions", [])

            third_party_packages = []
            if hasattr(result, "_extracted_files") and result._extracted_files:
                pkg_file = result._extracted_files.get("third_party_apps")
                if pkg_file and pkg_file.exists():
                    try:
                        content = pkg_file.read_text(encoding="utf-8", errors="replace")
                        for line in content.strip().split("\n"):
                            line = line.strip()
                            if line.startswith("package:"):
                                pkg = line.split(":", 1)[1]
                                if pkg:
                                    third_party_packages.append(pkg)
                    except Exception:
                        pass

            device_info = {}
            if hasattr(result, "_extracted_files") and result._extracted_files:
                info_file = result._extracted_files.get("device_info")
                if info_file and info_file.exists():
                    try:
                        content = info_file.read_text(encoding="utf-8", errors="replace")
                        for line in content.strip().split("\n"):
                            if "=" in line:
                                key, _, value = line.partition("=")
                                key = key.strip()
                                value = value.strip()
                                if key == "ro.product.model":
                                    device_info["model"] = value
                                elif key == "ro.build.version.release":
                                    device_info["android_version"] = value
                                elif key == "ro.build.type":
                                    device_info["build_type"] = value
                                elif key == "ro.debuggable":
                                    device_info["debuggable"] = value
                    except Exception:
                        pass

            recs = generate_recommendations(
                analysis_result=result,
                remediation_result=remediation_result,
                third_party_packages=third_party_packages,
                device_info=device_info,
            )

            self.after(0, self._show_recommendations, recs)
        except Exception as e:
            logger.warning(f"Failed to generate recommendations: {e}")

    # ============================================================
    # ROW 8: PROGRESS + TERMINAL
    # ============================================================

    def _build_progress_panel(self):
        frame = ctk.CTkFrame(self, corner_radius=10)
        frame.grid(row=8, column=0, padx=15, pady=(0, 8), sticky="nsew")
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(1, weight=1)

        top_row = ctk.CTkFrame(frame, fg_color="transparent")
        top_row.grid(row=0, column=0, padx=10, pady=(6, 3), sticky="ew")
        top_row.grid_columnconfigure(1, weight=1)

        self._progress_label = ctk.CTkLabel(
            top_row, text="Waiting for device...", font=ctk.CTkFont(size=13, weight="bold")
        )
        self._progress_label.grid(row=0, column=0, sticky="w")

        self._progress_percent = ctk.CTkLabel(
            top_row, text="0%", font=ctk.CTkFont(size=13, weight="bold"), text_color="#3B82F6"
        )
        self._progress_percent.grid(row=0, column=1, sticky="e")

        self._progress_bar = ctk.CTkProgressBar(top_row, height=8)
        self._progress_bar.grid(row=1, column=0, columnspan=2, pady=(4, 0), sticky="ew")
        self._progress_bar.set(0)

        self._terminal = ctk.CTkTextbox(
            frame, font=ctk.CTkFont(family="Consolas", size=10), state="disabled"
        )
        self._terminal.grid(row=1, column=0, padx=8, pady=(0, 8), sticky="nsew")

    # ============================================================
    # QUICK ACTION BUTTON HANDLERS
    # ============================================================

    def _set_buttons_scanning(self, text="SCANNING..."):
        self._quick_pull_btn.configure(state="disabled", text=text)
        self._quick_archive_btn.configure(state="disabled", text=text)
        self._quick_live_btn.configure(state="disabled", text=text)

    def _restore_quick_buttons(self):
        device_ok = self._device_state == DeviceState.READY
        self._quick_pull_btn.configure(
            state="normal" if device_ok else "disabled",
            text="PULL & SCAN PHONE",
        )
        self._quick_archive_btn.configure(
            state="normal",
            text="SCAN ARCHIVE",
        )
        self._quick_live_btn.configure(
            state="normal" if device_ok else "disabled",
            text="SCAN LIVE",
        )

    def _quick_pull_scan(self):
        """Pull bugreport from connected phone via ADB, save to temp, then scan."""
        if self._scan_running:
            return
        if self._device_state != DeviceState.READY:
            self._append_terminal("[ERROR] No device connected. Connect via USB first.")
            return
        if self._device_type_var.get() == "linux":
            self._append_terminal("[ERROR] PULL & SCAN not supported for Linux. Use SCAN LIVE.")
            return
        if self._device_type_var.get() == "ios":
            self._append_terminal("[INFO] iOS mode: running adapter scan...")
            self._mode_var.set("live")
            self._scan_running = True
            self._set_buttons_scanning("PULLING...")
            self._last_result = None
            self._clear_results()
            self._clear_navigator()
            self._clear_findings()
            logger.set_callback(self._on_log_message)
            thread = threading.Thread(
                target=self._adapter_scan_worker, args=("ios", self._profile_var.get()), daemon=True,
            )
            thread.start()
            return

        self._scan_running = True
        self._last_progress = 0.0
        self._mode_var.set("live")
        self._set_buttons_scanning("PULLING...")
        self._last_result = None
        self._clear_results()
        self._clear_navigator()
        self._clear_findings()
        logger.set_callback(self._on_log_message)
        self._append_terminal("[INFO] Pulling bugreport from phone... (may take 60-120s)")

        def _worker():
            tmp_dir = None
            try:
                tmp_dir = Path(tempfile.mkdtemp(prefix="forensic_pull_"))
                bugreport_zip = tmp_dir / "bugreport.zip"

                serial = self._device_serial or ""
                cmd = [ADB_BINARY]
                if serial:
                    cmd += ["-s", serial]
                cmd += ["bugreport", str(bugreport_zip)]

                self.after(0, self._append_terminal, f"[INFO] Running: {' '.join(cmd)}")
                subprocess.run(
                    cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                    timeout=180,
                )

                if not bugreport_zip.exists() or bugreport_zip.stat().st_size == 0:
                    self.after(0, self._append_terminal,
                               "[WARN] adb bugreport failed, trying bugreportz fallback...")
                    fallback_cmd = [ADB_BINARY]
                    if serial:
                        fallback_cmd += ["-s", serial]
                    fallback_cmd += ["shell", "bugreportz", "-p"]

                    proc2 = subprocess.run(
                        fallback_cmd, capture_output=True, text=True,
                        encoding="utf-8", errors="replace", timeout=180,
                    )
                    remote_path = proc2.stdout.strip().split("\n")[-1].strip()

                    if remote_path.startswith("/"):
                        pull_cmd = [ADB_BINARY]
                        if serial:
                            pull_cmd += ["-s", serial]
                        pull_cmd += ["pull", remote_path, str(bugreport_zip)]
                        subprocess.run(
                            pull_cmd, capture_output=True, text=True,
                            encoding="utf-8", errors="replace", timeout=120,
                        )

                if not bugreport_zip.exists() or bugreport_zip.stat().st_size == 0:
                    self.after(0, self._append_terminal,
                               "[ERROR] Failed to pull bugreport from device")
                    return

                size_mb = bugreport_zip.stat().st_size / (1024 * 1024)
                self.after(0, self._append_terminal,
                           f"[OK] Bugreport pulled: {size_mb:.1f} MB")

                archive_path = tmp_dir / "bugreport_archive.zip"
                with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as zf:
                    zf.write(bugreport_zip, "bugreport.zip")
                    manifest_lines = [
                        "Archive Type: Bugreport",
                        f"Case ID: {self._case_entry.get().strip() or 'auto'}",
                        f"Device Serial: {serial}",
                        "Source: bugreport (ADB live pull)",
                        f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}",
                        f"Bugreport Size: {size_mb:.1f} MB",
                    ]
                    zf.writestr("MANIFEST.txt", "\n".join(manifest_lines))

                self.after(0, self._append_terminal,
                           "[OK] Archive created, starting scan...")
                self._run_archive_scan(archive_path, tmp_dir)

            except subprocess.TimeoutExpired:
                self.after(0, self._append_terminal,
                           "[ERROR] Bugreport timed out (180s). Phone may be slow or locked.")
            except Exception as e:
                self.after(0, self._append_terminal, f"[ERROR] Pull & scan failed: {e}")
            finally:
                self._scan_running = False
                self.after(0, self._restore_quick_buttons)

        threading.Thread(target=_worker, daemon=True).start()

    def _quick_scan_archive(self):
        """Open file picker for .zip, scan the selected archive."""
        if self._scan_running:
            return

        path = filedialog.askopenfilename(
            title="Select bugreport ZIP or backup archive",
            filetypes=[
                ("Archives", "*.zip *.tar *.tar.gz *.tgz"),
                ("All files", "*.*"),
            ],
        )
        if not path:
            return

        archive_path = Path(path)
        size_mb = archive_path.stat().st_size / (1024 * 1024)
        self._append_terminal(f"[INFO] Selected archive: {archive_path.name} ({size_mb:.1f} MB)")

        self._scan_running = True
        self._last_progress = 0.0
        self._usb_monitor.pause()
        self._mode_var.set("offline")
        self._set_buttons_scanning("SCANNING...")
        self._last_result = None
        self._clear_results()
        self._clear_navigator()
        self._clear_findings()
        logger.set_callback(self._on_log_message)

        def _worker():
            try:
                self._run_archive_scan(archive_path)
            except Exception as e:
                self.after(0, self._append_terminal, f"[ERROR] Archive scan failed: {e}")
            finally:
                self._scan_running = False
                self.after(0, self._restore_quick_buttons)

        threading.Thread(target=_worker, daemon=True).start()

    def _quick_scan_live(self):
        """Scan connected phone directly via ADB without archiving."""
        if self._scan_running:
            self._append_terminal("[WARN] Live scan ignored: another scan is already running")
            return
        self._append_terminal("[LIVE] Scan button accepted; starting live acquisition...")
        if self._device_state != DeviceState.READY:
            self._append_terminal("[ERROR] No device connected. Connect via USB first.")
            return

        device_type = self._device_type_var.get()

        self._scan_running = True
        self._last_progress = 0.0
        self._mode_var.set("live")
        self._set_buttons_scanning("SCANNING...")
        self._last_result = None
        self._clear_results()
        self._clear_navigator()
        self._clear_findings()
        logger.set_callback(self._on_log_message)

        if device_type == "linux":
            if not self._linux_target:
                self._append_terminal("[ERROR] No Linux target set. Set target in Advanced Options.")
                self._scan_running = False
                self._restore_quick_buttons()
                return
            thread = threading.Thread(
                target=self._adapter_scan_worker,
                args=("linux", self._profile_var.get()), daemon=True,
            )
            thread.start()
        elif device_type == "ios":
            thread = threading.Thread(
                target=self._adapter_scan_worker,
                args=("ios", self._profile_var.get()), daemon=True,
            )
            thread.start()
        else:
            try:
                profile = self._profile_var.get()
                cmds = get_profile_commands(profile)
                thread = threading.Thread(
                    target=self._scan_worker, args=(profile, len(cmds)), daemon=True,
                    name="android-live-scan",
                )
                thread.start()
                self._append_terminal("[LIVE] Acquisition worker started")
            except Exception as exc:
                self._scan_running = False
                self._append_terminal(f"[ERROR] Live scan startup failed: {exc}")
                self._restore_quick_buttons()

    # ============================================================
    # ARCHIVE SCAN ENGINE (shared by pull-scan and archive-scan)
    # ============================================================

    def _run_archive_scan(self, archive_path: Path, tmp_dir: Path | None = None):
        """Ingest archive and run full analysis pipeline."""
        self._usb_monitor.pause()
        lifecycle = ScanLifecycle()
        self._scan_lifecycle = lifecycle
        result = None
        try:
            from archive_engine import ingest_archive
            case_id = self._case_entry.get().strip() or f"scan_{int(time.time())}"

            lifecycle.transition(ScanStage.INGESTING)
            self.after(0, self._append_terminal,
                       f"[INFO] Ingesting archive: {archive_path.name}...")
            self.after(0, self._update_progress, 5, f"Ingesting archive: {archive_path.name}...")

            info = run_with_timeout(
                ScanStage.INGESTING,
                300,
                lambda: ingest_archive(archive_path, case_id=case_id),
            )
            extract_result = info["results"]
            self._dump_dir = info.get("extract_dir")

            self._artifact_map = info.get("artifact_map", [])
            self.after(0, self._update_navigator)

            if not extract_result:
                raise RuntimeError("archive ingestion produced no analyzable artifacts")

            self.after(0, self._append_terminal,
                       f"[OK] Extracted: {len(self._artifact_map)} artifacts indexed")

            lifecycle.transition(ScanStage.ANALYZING)
            self.after(0, self._update_progress, 20, "Running YARA + heuristics...")
            result = analyze(
                extracted_files=extract_result,
                device_serial=case_id,
                check_virustotal=self._vt_var.get(),
                on_progress=self._scaled_progress_bridge(20, 70, "Analysis"),
                dump_dir=self._dump_dir,
                run_mvt=self._mvt_var.get(),
                run_aleapp=self._aleapp_var.get(),
                run_capa=self._capa_var.get(),
                run_apkid=self._apkid_var.get(),
                run_quark=self._quark_var.get(),
                run_intel=self._intel_var.get(),
                run_entropy=getattr(self, '_entropy_var', None) and self._entropy_var.get(),
                run_browser=getattr(self, '_browser_var', None) and self._browser_var.get(),
                run_correlation=getattr(self, '_correlation_var', None) and self._correlation_var.get(),
            )

            lifecycle.transition(ScanStage.REMEDIATING)
            self.after(0, self._update_progress, 72, "Running remediation analysis...")
            from remediation_engine import analyze_remediation
            try:
                remed = run_with_timeout(
                    ScanStage.REMEDIATING,
                    30,
                    lambda: analyze_remediation(result),
                )
                self._remediation_actions = remed.actions
                result._remediation = remed.to_dict()
            except StageTimeoutError:
                raise
            except Exception as exc:
                lifecycle.warnings.append(f"Remediation analysis failed: {exc}")

            if self._save_var.get() and self._dump_dir:
                lifecycle.transition(ScanStage.REPORTING)
                self.after(0, self._update_progress, 78, "Generating JSON scan report...")
                try:
                    report_path = run_with_timeout(
                        ScanStage.REPORTING,
                        30,
                        lambda: save_report(result, self._dump_dir),
                    )
                    self.after(0, self._append_terminal, f"[OK] Report saved: {report_path.name}")
                except StageTimeoutError:
                    raise
                except Exception as exc:
                    lifecycle.warnings.append(f"Report generation failed: {exc}")

            if self._timeline_var.get() and self._dump_dir:
                lifecycle.transition(ScanStage.TIMELINE)
                self.after(0, self._update_progress, 84, "Generating forensic timeline...")
                from extractor import get_profile_commands as _gpc
                from timeline import build_timeline
                try:
                    timeline_path = run_with_timeout(
                        ScanStage.TIMELINE,
                        180,
                        lambda: build_timeline(
                            extract_result,
                            self._dump_dir,
                            manifest_metadata=_gpc(self._profile_var.get()),
                        ),
                    )
                    if timeline_path:
                        self.after(0, self._append_terminal, f"[OK] Timeline: {timeline_path.name}")
                    else:
                        lifecycle.warnings.append("Timeline contained no timestamped events")
                except StageTimeoutError:
                    raise
                except Exception as exc:
                    lifecycle.warnings.append(f"Timeline generation failed: {exc}")

            if self._encrypt_var.get() and self._dump_dir and result.verdict in ("CRITICAL", "SUSPICIOUS"):
                from custody import encrypt_dump
                enc_path = run_with_timeout(
                    ScanStage.FINALIZING,
                    300,
                    lambda: encrypt_dump(self._dump_dir, case_id=case_id),
                )
                self.after(0, self._append_terminal, f"[OK] Evidence ZIP: {enc_path.name}")

            if (self._dump_dir and result.verdict == "SUSPICIOUS"
                    and hasattr(result, "composite_risk_score")
                    and result.composite_risk_score >= 40):
                try:
                    from custody import create_evidence_package, record_tool_result
                    tool_results = []
                    for r in result.matched_rules:
                        sev = "HIGH" if any(t in ("credential_theft", "data_exfil", "stalkerware",
                                                   "disguised_package") for t in r.get("tags", [])) else "MEDIUM"
                        tool_results.append(record_tool_result("yara", {
                            "rule": r.get("rule"), "file": r.get("file"),
                            "tags": r.get("tags"), "severity": sev,
                        }))
                    if result.heuristic_result:
                        tool_results.append(record_tool_result("heuristics", result.heuristic_result))
                    for ent in result.entropy_results:
                        tool_results.append(record_tool_result("entropy", ent))
                    for browser in result.browser_results:
                        tool_results.append(record_tool_result("browser", browser))
                    if result.correlation_result:
                        tool_results.append(record_tool_result("correlation", result.correlation_result))
                    evidence_path = create_evidence_package(
                        self._dump_dir, tool_results,
                        case_id=case_id or "auto",
                    )
                    self.after(0, self._append_terminal, f"[OK] Evidence locked: {evidence_path.name}")
                except Exception as e:
                    self.after(0, self._append_terminal, f"[WARN] Auto-evidence lock failed: {e}")

            unavailable = sorted(
                name for name, status in getattr(result, "tool_status", {}).items()
                if status in ("error", "unavailable")
            )
            if unavailable:
                lifecycle.warnings.append(f"Analyzers unavailable or failed: {', '.join(unavailable)}")

            lifecycle.transition(ScanStage.FINALIZING)
            terminal = (
                ScanStage.COMPLETED_WITH_WARNINGS
                if lifecycle.warnings
                else ScanStage.COMPLETED
            )
            lifecycle.transition(terminal)
            self._last_result = result
            self.after(0, self._finalize_scan_ui, result, lifecycle)

        except StageTimeoutError as exc:
            lifecycle.transition(ScanStage.TIMED_OUT, error=str(exc))
            self.after(0, self._finalize_scan_ui, result, lifecycle)
        except Exception as e:
            if not lifecycle.is_terminal:
                lifecycle.transition(ScanStage.FAILED, error=str(e))
            self.after(0, self._finalize_scan_ui, result, lifecycle)
        finally:
            if self._dump_dir and result is None:
                cleanup_dump_dir(self._dump_dir)
            self._usb_monitor.resume()

    def _on_progress_bridge(self, percent: float, message: str):
        """Bridge for analyze() on_progress callback (called from thread)."""
        self.after(0, self._update_progress, percent, message)

    def _scaled_progress_bridge(self, start: float, end: float, stage_name: str):
        """Map component-local progress into a monotonic GUI stage range."""
        span = end - start

        def bridge(percent: float, message: str):
            bounded = max(0.0, min(float(percent), 100.0))
            overall = start + (bounded / 100.0) * span
            self.after(0, self._update_progress, overall, f"{stage_name}: {message}")

        return bridge

    def _finalize_scan_ui(self, result, lifecycle: ScanLifecycle):
        """Single UI-thread terminal callback; always restores controls and status."""
        try:
            if result is not None:
                self._update_navigator_status(result)
                self._show_results(result)
            for warning in lifecycle.warnings:
                self._append_terminal(f"[WARN] {warning}")
            if lifecycle.error:
                self._append_terminal(f"[ERROR] {lifecycle.error}")
        except Exception as exc:
            self._append_terminal(f"[ERROR] Final result rendering failed: {exc}")
            if lifecycle.stage in (ScanStage.COMPLETED, ScanStage.COMPLETED_WITH_WARNINGS):
                lifecycle = ScanLifecycle()
                lifecycle.transition(ScanStage.FAILED, error=f"Final result rendering failed: {exc}")
        finally:
            label = lifecycle.stage.value.upper()
            self._update_progress(100, label)
            if getattr(self, "_live_scan_active", False):
                self._append_terminal("[LIVE] GUI finalization executed")
                self._live_scan_active = False
            self._scan_running = False
            self._restore_quick_buttons()

    # ============================================================
    # SCAN WORKERS (backward compat + used by quick buttons)
    # ============================================================

    def _start_scan(self):
        """Legacy scan starter for backward compatibility."""
        if self._scan_running:
            return

        mode = self._mode_var.get()
        device_type = self._device_type_var.get()

        if mode == "offline":
            pass
        elif device_type == "linux":
            if not self._linux_target:
                return
        elif device_type == "ios":
            pass
        else:
            if self._device_state != DeviceState.READY:
                return

        self._scan_running = True
        self._set_buttons_scanning("SCANNING...")
        self._last_result = None
        self._clear_results()
        self._clear_navigator()
        self._clear_findings()

        logger.set_callback(self._on_log_message)

        if mode == "offline":
            self._usb_monitor.pause()
            thread = threading.Thread(target=self._offline_scan_worker, daemon=True)
        elif device_type == "ios":
            profile = self._profile_var.get()
            thread = threading.Thread(
                target=self._adapter_scan_worker, args=("ios", profile), daemon=True
            )
        elif device_type == "linux":
            profile = self._profile_var.get()
            thread = threading.Thread(
                target=self._adapter_scan_worker, args=("linux", profile), daemon=True
            )
        else:
            profile = self._profile_var.get()
            cmds = get_profile_commands(profile)
            thread = threading.Thread(
                target=self._scan_worker, args=(profile, len(cmds)), daemon=True
            )
        thread.start()

    def _scan_worker(self, profile: str, cmd_count: int):
        lifecycle = ScanLifecycle()
        self._live_scan_active = True
        self._scan_lifecycle = lifecycle
        result = None
        try:
            lifecycle.transition(ScanStage.INGESTING)
            self._update_progress(0, f"Starting extraction ({cmd_count} artifacts)...")
            extracted = run_extraction(
                serial=self._device_serial,
                profile=profile,
                on_progress=self._on_progress_bridge,
            )
            self._dump_dir = Path(list(extracted.values())[0]).parent if extracted else None

            self._artifact_map = []
            for _key, fpath in extracted.items():
                fpath = Path(fpath)
                if fpath.exists():
                    size = fpath.stat().st_size
                    self._artifact_map.append({
                        "name": fpath.name,
                        "path": str(fpath),
                        "relative_path": fpath.name,
                        "size_bytes": size,
                        "size_human": _human_size(size),
                        "status": "CLEAN",
                        "extension": fpath.suffix.lower(),
                        "has_content": True,
                    })
            self.after(0, self._update_navigator)

            pcap_result = None
            if self._pcap_var.get() and self._device_serial:
                self._update_progress(60, "Capturing live PCAP (60s)...")
                try:
                    from pcap_bridge import PCAPBridge
                    bridge = PCAPBridge(self._device_serial, duration=60)
                    pcap_result = bridge.capture(on_progress=self._on_progress_bridge)
                except Exception as e:
                    self.after(0, self._append_terminal, f"[WARN] PCAP failed: {e}")

            lifecycle.transition(ScanStage.ANALYZING)
            self._update_progress(75, "Starting threat analysis...")
            result = analyze(
                extracted_files=extracted,
                device_serial=self._device_serial or "",
                check_virustotal=self._vt_var.get(),
                on_progress=self._on_progress_bridge,
                dump_dir=self._dump_dir,
                run_mvt=self._mvt_var.get(),
                run_aleapp=self._aleapp_var.get(),
                run_capa=self._capa_var.get(),
                run_apkid=self._apkid_var.get(),
                run_quark=self._quark_var.get(),
                run_intel=self._intel_var.get(),
                run_entropy=getattr(self, '_entropy_var', None) and self._entropy_var.get(),
                run_browser=getattr(self, '_browser_var', None) and self._browser_var.get(),
                run_correlation=getattr(self, '_correlation_var', None) and self._correlation_var.get(),
                device_type=self._device_type_var.get(),
            )

            if pcap_result:
                result.pcap_results = pcap_result
                from analyzer import _compute_verdict as _cv
                result.verdict = _cv(result)
                result.summary = _rebuild_summary(result)

            lifecycle.transition(ScanStage.REMEDIATING)
            self._update_progress(85, "Running remediation analysis...")
            from remediation_engine import analyze_remediation
            self.after(0, self._append_terminal, "[LIVE] Remediation started")
            try:
                remed = run_with_timeout(
                    ScanStage.REMEDIATING, 30, lambda: analyze_remediation(result)
                )
                self._remediation_actions = remed.actions
                result._remediation = remed.to_dict()
                self.after(0, self._append_terminal, "[LIVE] Remediation completed")
            except StageTimeoutError:
                raise
            except Exception as exc:
                lifecycle.warnings.append(f"Remediation analysis failed: {exc}")

            if self._save_var.get() and self._dump_dir:
                lifecycle.transition(ScanStage.REPORTING)
                self.after(0, self._append_terminal, "[LIVE] JSON export started")
                try:
                    report_path = run_with_timeout(
                        ScanStage.REPORTING, 30,
                        lambda: save_report(result, self._dump_dir),
                    )
                    self.after(0, self._append_terminal, "[LIVE] JSON export completed")
                    self.after(0, self._append_terminal, f"[OK] Report saved: {report_path.name}")
                except StageTimeoutError:
                    raise
                except Exception as exc:
                    lifecycle.warnings.append(f"Report generation failed: {exc}")

            if self._timeline_var.get() and self._dump_dir:
                lifecycle.transition(ScanStage.TIMELINE)
                self.after(0, self._append_terminal, "[LIVE] CSV export started")
                from timeline import build_timeline
                try:
                    timeline_path = run_with_timeout(
                        ScanStage.TIMELINE, 180,
                        lambda: build_timeline(
                            extracted, self._dump_dir,
                            manifest_metadata=extractor_manifest_meta(profile),
                        ),
                    )
                    self.after(0, self._append_terminal, "[LIVE] CSV export completed")
                    if timeline_path:
                        self.after(0, self._append_terminal, f"[OK] Timeline: {timeline_path.name}")
                except StageTimeoutError:
                    raise
                except Exception as exc:
                    lifecycle.warnings.append(f"Timeline generation failed: {exc}")

            if self._encrypt_var.get() and self._dump_dir and result.verdict in ("CRITICAL", "SUSPICIOUS"):
                from custody import encrypt_dump
                enc_path = encrypt_dump(self._dump_dir, case_id=self._case_entry.get().strip())
                self.after(0, self._append_terminal, f"[OK] Evidence ZIP: {enc_path.name}")

            if (self._dump_dir and result.verdict == "SUSPICIOUS"
                    and hasattr(result, "composite_risk_score")
                    and result.composite_risk_score >= 40):
                try:
                    from custody import create_evidence_package, record_tool_result
                    tool_results = []
                    for r in result.matched_rules:
                        sev = "HIGH" if any(t in ("credential_theft", "data_exfil", "stalkerware",
                                                   "disguised_package") for t in r.get("tags", [])) else "MEDIUM"
                        tool_results.append(record_tool_result("yara", {
                            "rule": r.get("rule"), "file": r.get("file"),
                            "tags": r.get("tags"), "severity": sev,
                        }))
                    if result.heuristic_result:
                        tool_results.append(record_tool_result("heuristics", result.heuristic_result))
                    for ent in result.entropy_results:
                        tool_results.append(record_tool_result("entropy", ent))
                    for browser in result.browser_results:
                        tool_results.append(record_tool_result("browser", browser))
                    if result.correlation_result:
                        tool_results.append(record_tool_result("correlation", result.correlation_result))
                    evidence_path = create_evidence_package(
                        self._dump_dir, tool_results,
                        case_id=self._case_entry.get().strip() or "auto",
                    )
                    self.after(0, self._append_terminal, f"[OK] Evidence locked: {evidence_path.name}")
                except Exception as e:
                    self.after(0, self._append_terminal, f"[WARN] Auto-evidence lock failed: {e}")

            self._last_result = result
            lifecycle.transition(ScanStage.FINALIZING)
            terminal = ScanStage.COMPLETED_WITH_WARNINGS if lifecycle.warnings else ScanStage.COMPLETED
            lifecycle.transition(terminal)
            self.after(0, self._append_terminal, "[LIVE] GUI finalization scheduled")
            self.after(0, self._finalize_scan_ui, result, lifecycle)

        except StageTimeoutError as exc:
            lifecycle.transition(ScanStage.TIMED_OUT, error=str(exc))
            self.after(0, self._finalize_scan_ui, result, lifecycle)
        except Exception as e:
            lifecycle.transition(ScanStage.FAILED, error=str(e))
            self.after(0, self._finalize_scan_ui, result, lifecycle)
        finally:
            if self._dump_dir and not self._last_result:
                cleanup_dump_dir(self._dump_dir)
            self.after(0, self._append_terminal, "[LIVE] Worker terminated")

    def _adapter_scan_worker(self, os_type: str, profile: str):
        """Scan worker for non-Android adapters (iOS, Linux/Docker)."""
        try:
            from adapters import AdapterRegistry
            adapter = AdapterRegistry.get_by_os(os_type)
            if not adapter:
                self.after(0, self._append_terminal, f"[ERROR] No adapter found for {os_type}")
                return

            self._update_progress(0, f"Starting {adapter.name} extraction...")
            serial = self._linux_target if os_type == "linux" else ""
            extracted = adapter.extract(
                serial=serial, profile=profile, on_progress=self._on_progress_bridge,
            )

            if not extracted:
                self.after(0, self._append_terminal, f"[ERROR] {adapter.name} extraction failed")
                return

            self._dump_dir = Path(list(extracted.values())[0]).parent if extracted else None

            self._artifact_map = []
            for _key, fpath in extracted.items():
                fpath = Path(fpath)
                if fpath.exists():
                    size = fpath.stat().st_size
                    self._artifact_map.append({
                        "name": fpath.name,
                        "path": str(fpath),
                        "relative_path": fpath.name,
                        "size_bytes": size,
                        "size_human": _human_size(size),
                        "status": "CLEAN",
                        "extension": fpath.suffix.lower(),
                        "has_content": True,
                    })
            self.after(0, self._update_navigator)

            self._update_progress(75, "Starting threat analysis...")
            result = analyze(
                extracted_files=extracted,
                device_serial=serial or adapter.name,
                check_virustotal=self._vt_var.get(),
                on_progress=self._on_progress_bridge,
                run_mvt=self._mvt_var.get(),
                run_aleapp=self._aleapp_var.get(),
                run_capa=self._capa_var.get(),
                run_apkid=self._apkid_var.get(),
                run_quark=self._quark_var.get(),
                run_intel=self._intel_var.get(),
                run_entropy=getattr(self, '_entropy_var', None) and self._entropy_var.get(),
                run_browser=getattr(self, '_browser_var', None) and self._browser_var.get(),
                run_correlation=getattr(self, '_correlation_var', None) and self._correlation_var.get(),
                device_type=os_type.lower(),
            )

            self._update_progress(85, "Running remediation analysis...")
            from remediation_engine import analyze_remediation
            remed = analyze_remediation(result)
            self._remediation_actions = remed.actions
            result._remediation = remed.to_dict()

            if self._save_var.get() and self._dump_dir:
                report_path = save_report(result, self._dump_dir)
                self.after(0, self._append_terminal, f"[OK] Report saved: {report_path.name}")

            self._last_result = result
            self.after(0, self._show_results, result)

        except Exception as e:
            self.after(0, self._append_terminal, f"[ERROR] {os_type} scan failed: {e}")
        finally:
            if self._dump_dir and not self._last_result:
                cleanup_dump_dir(self._dump_dir)
            self._scan_running = False
            self.after(0, self._restore_quick_buttons)

    def _offline_scan_worker(self):
        if not self._offline_archive:
            lifecycle = ScanLifecycle()
            lifecycle.transition(ScanStage.FAILED, error="No archive selected")
            self.after(0, self._finalize_scan_ui, None, lifecycle)
            return
        self._run_archive_scan(self._offline_archive)

    # ============================================================
    # CONTAINMENT
    # ============================================================

    def _contain_threat(self):
        """Run automated incident containment (DNS sinkhole + app isolation + evidence lock)."""
        if not self._dump_dir or not self._last_result:
            self._append_terminal("[ERROR] No scan results. Run a scan first.")
            return

        verdict = self._last_result.verdict if hasattr(self._last_result, 'verdict') else "CLEAN"
        if verdict == "CLEAN":
            self._append_terminal("[INFO] Device is CLEAN — no containment needed.")
            return

        self._append_terminal("[INFO] Running automated incident containment...")

        def _worker():
            try:
                from containment_engine import ContainmentEngine

                engine = ContainmentEngine(serial=self._device_serial or "")

                suspicious_pkgs = []
                for pkg in (self._last_result.heuristic_result or {}).get("suspicious_packages", []):
                    if isinstance(pkg, str):
                        suspicious_pkgs.append(pkg)

                report = engine.contain_threat(
                    threat_verdict=verdict,
                    suspicious_packages=suspicious_pkgs,
                    suspicious_ips=getattr(
                        self._last_result, 'suspicious_ips', []
                    ),
                    dump_dir=self._dump_dir,
                )

                self.after(0, self._append_terminal, f"[CONTAIN] {report.summary}")
                for action in report.actions_taken:
                    self.after(
                        0, self._append_terminal,
                        f"  [EXECUTED] {action['action_type']}: {action['details']}",
                    )
                for action in report.actions_recommended:
                    detail = action['details'][:80]
                    self.after(
                        0, self._append_terminal,
                        f"  [RECOMMENDED] {action['action_type']}: {detail}",
                    )

            except Exception as e:
                self.after(0, self._append_terminal, f"[ERROR] Containment failed: {e}")

        threading.Thread(target=_worker, daemon=True).start()

    # ============================================================
    # DEVICE STATE CALLBACK
    # ============================================================

    def _on_device_state(self, state: str, serial: str | None):
        def _update():
            self._device_state = state
            self._device_serial = serial
            color = STATE_COLORS.get(state, "#e74c3c")
            label = STATE_LABELS.get(state, "UNKNOWN")

            self._status_dot.configure(text_color=color)
            self._status_label.configure(text=label)

            if state == DeviceState.READY and serial:
                info = self._usb_monitor.device_info
                brand = info.get("brand", "")
                model = info.get("model", "")
                android = info.get("android", "")
                parts = [p for p in [brand, model] if p]
                device_str = " ".join(parts) if parts else serial
                detail = f"{device_str} | Serial: {serial}"
                if android:
                    detail += f" | Android {android}"
                self._serial_label.configure(text=detail)
                self._append_terminal(f"[OK] Device ready: {detail}")
            elif state == DeviceState.UNAUTHORIZED:
                self._serial_label.configure(text="Device locked. Unlock & allow USB debugging.")
                self._append_terminal("[!] Device unauthorized. Accept RSA prompt on phone.")
            else:
                self._serial_label.configure(text="No device detected. Connect via USB.")

            self._restore_quick_buttons()

        self.after(0, _update)

    # ============================================================
    # SHARED UTILITIES
    # ============================================================

    def _update_progress(self, percent: float, message: str):
        percent = max(self._last_progress, min(float(percent), 100.0))
        self._last_progress = percent
        self._progress_bar.set(percent / 100)
        self._progress_percent.configure(text=f"{int(percent)}%")
        self._progress_label.configure(text=message)
        self._append_terminal(f"[{int(percent)}%] {message}")

    def _on_log_message(self, level: str, message: str):
        prefix_map = {
            "info": "[INFO]", "warning": "[WARN]",
            "error": "[ERROR]", "success": "[OK]",
        }
        prefix = prefix_map.get(level, "[LOG]")
        self.after(0, self._append_terminal, f"{prefix} {message}")

    def _append_terminal(self, text: str):
        self._terminal.configure(state="normal")
        self._terminal.insert("end", text + "\n")
        self._terminal.see("end")
        self._terminal.configure(state="disabled")

    def _clear_results(self):
        self._results_text.configure(state="normal")
        self._results_text.delete("1.0", "end")
        self._results_text.configure(state="disabled")
        self._clear_navigator()
        self._clear_findings()

    def _show_scan_history(self):
        try:
            from history_db import get_recent_scans
            scans = get_recent_scans(limit=20)
        except Exception:
            scans = []
        self._terminal.configure(state="normal")
        self._terminal.delete("1.0", "end")
        if not scans:
            self._terminal.insert("end", "No scan history found.\n")
        else:
            self._terminal.insert(
                "end",
                f"{'ID':>4}  {'Timestamp':<22} {'Verdict':<12} "
                f"{'Risk':>4}  {'YARA':>4}  {'IPs':>4}\n"
            )
            self._terminal.insert("end", "-" * 70 + "\n")
            for s in scans:
                self._terminal.insert(
                    "end",
                    f"{s['id']:>4}  {s['timestamp_utc']:<22} {s['verdict']:<12} "
                    f"{s.get('risk_score', 0):>4}  {s.get('yara_match_count', 0):>4}  "
                    f"{s.get('suspicious_ip_count', 0):>4}\n"
                )
        self._terminal.configure(state="disabled")

    def _on_close(self):
        self._usb_monitor.stop()
        if self._dump_dir and self._dump_dir.exists():
            cleanup_dump_dir(self._dump_dir)
        self.destroy()

    def _sync_ioc_feeds(self):
        def _worker():
            try:
                results = sync_ioc_feeds()
                total_new = sum(r.get("new_ips", 0) for r in results.values())
                if total_new > 0:
                    self.after(0, self._append_terminal,
                               f"[OK] IOC feeds synced: +{total_new} new threat IPs")
                else:
                    self.after(0, self._append_terminal,
                               "[OK] IOC feeds: already up to date")
            except Exception as e:
                self.after(0, self._append_terminal,
                           f"[WARN] IOC sync failed: {e}")
        threading.Thread(target=_worker, daemon=True).start()

    @staticmethod
    def _open_in_explorer(path: str):
        try:
            subprocess.Popen(["explorer", "/select,", str(path)])
        except Exception:
            pass


def extractor_manifest_meta(profile: str) -> list[dict]:
    from extractor import get_profile_commands
    return get_profile_commands(profile)


def _rebuild_summary(result) -> str:
    from analyzer import _build_summary
    return _build_summary(result)


def _human_size(size_bytes: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"


def main():
    app = ForensicScannerApp()
    app.mainloop()


if __name__ == "__main__":
    main()
