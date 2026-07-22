# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for Universal Forensic Scanner v7.0.
Builds a one-directory distribution with GUI + CLI + all assets."""

import os
import sys
import glob
import customtkinter

block_cipher = None

# Find Tcl/Tk in venv or system Python
_tcltk_candidates = [
    os.path.join(sys.prefix, "tcl"),
    os.path.join(os.path.dirname(sys.executable), "..", "tcl"),
]
TCLTK_DIR = None
for c in _tcltk_candidates:
    if os.path.isdir(os.path.join(c, "tcl8.6")):
        TCLTK_DIR = c
        break
if TCLTK_DIR is None:
    for pattern in [
        r"C:\Python*\tcl",
        r"C:\Users\*\AppData\Local\Programs\Python\Python*\tcl",
    ]:
        for m in glob.glob(pattern):
            if os.path.isdir(os.path.join(m, "tcl8.6")):
                TCLTK_DIR = m
                break
        if TCLTK_DIR:
            break

ctk_assets = os.path.join(os.path.dirname(customtkinter.__file__), "assets")

datas = [
    (os.path.join(TCLTK_DIR, "tcl8.6"), "tcl8.6"),
    (os.path.join(TCLTK_DIR, "tk8.6"), "tk8.6"),
    ("rules", "rules"),
    ("manifests", "manifests"),
    ("docs", "docs"),
    ("scripts", "scripts"),
    ("adapters", "adapters"),
    ("domain", "domain"),
    ("compat", "compat"),
    (ctk_assets, "customtkinter/assets"),
]

hiddenimports = [
    "customtkinter",
    "tkinter",
    "tkinter.filedialog",
    "tkinter.messagebox",
    "adapters",
    "adapters.android_adapter",
    "adapters.ios_adapter",
    "adapters.linux_docker_adapter",
    "adapters.base_adapter",
    "domain",
    "domain.artifact",
    "domain.event",
    "domain.finding",
    "domain.enums",
    "domain.scan_result",
    "domain.scan_context",
    "compat",
    "compat.v6_models",
    "archive_engine",
    "analyzer",
    "extractor",
    "core",
    "usb_monitor",
    "scan_lifecycle",
    "scan_offline",
    "history_db",
    "timeline",
    "yara_context",
    "yara_diagnostics",
    "heuristics",
    "ioc_sync",
    "containment_engine",
    "remediation_engine",
    "custody",
    "correlation_engine",
    "mvt_bridge",
    "aleapp_bridge",
    "capa_bridge",
    "apkid_bridge",
    "quark_bridge",
    "intel_bridge",
    "entropy_bridge",
    "pcap_bridge",
    "browser_forensics_bridge",
    "mobsf_bridge",
    "mock_adb",
]

excludes = [
    "matplotlib", "numpy", "scipy", "pandas",
    "PIL", "pytest", "mypy", "ruff",
]

# GUI Analysis (app.py)
gui_a = Analysis(
    ["app.py"],
    pathex=["."],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=excludes,
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

gui_pyz = PYZ(gui_a.pure, gui_a.zipped_data, cipher=block_cipher)

gui_exe = EXE(
    gui_pyz,
    gui_a.scripts,
    [],
    exclude_binaries=True,
    name="UniversalForensicScanner",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
)

# CLI Analysis (cli.py)
cli_a = Analysis(
    ["cli.py"],
    pathex=["."],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=excludes,
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

cli_pyz = PYZ(cli_a.pure, cli_a.zipped_data, cipher=block_cipher)

cli_exe = EXE(
    cli_pyz,
    cli_a.scripts,
    [],
    exclude_binaries=True,
    name="UniversalForensicScanner_CLI",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
)

# Combine both into a single directory distribution
coll = COLLECT(
    gui_exe,
    cli_exe,
    gui_a.binaries,
    gui_a.zipfiles,
    gui_a.datas,
    cli_a.binaries,
    cli_a.zipfiles,
    cli_a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="UniversalForensicScanner",
)
