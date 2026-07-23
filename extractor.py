import json
from pathlib import Path

import core
from core import ADB_TIMEOUT, create_dump_dir

MANIFEST_PATH = Path(__file__).parent / "manifests" / "android_artifacts.json"
LEGACY_MANIFEST_PATH = Path(__file__).parent / "manifests" / "artifacts.json"


def load_manifest() -> dict:
    """Load and validate the artifacts manifest."""
    path = MANIFEST_PATH if MANIFEST_PATH.exists() else LEGACY_MANIFEST_PATH
    if not path.exists():
        raise FileNotFoundError(f"No manifest found: {MANIFEST_PATH} or {LEGACY_MANIFEST_PATH}")
    with open(path, encoding="utf-8") as f:
        manifest = json.load(f)
    if "profiles" not in manifest:
        raise ValueError("Manifest missing 'profiles' key")
    return manifest


def get_profile_names() -> list[str]:
    """Return available profile names."""
    manifest = load_manifest()
    return list(manifest["profiles"].keys())


def get_profile_commands(profile: str) -> list[dict]:
    """Return the command list for a given profile."""
    manifest = load_manifest()
    if profile not in manifest["profiles"]:
        raise ValueError(f"Unknown profile: {profile}. Available: {list(manifest['profiles'].keys())}")
    return manifest["profiles"][profile]["commands"]


class Extractor:
    """Dynamic manifest-driven forensic artifact extractor."""

    def __init__(self, serial: str, profile: str = "deep", on_progress=None):
        self._serial = serial
        self._profile = profile
        self._on_progress = on_progress
        self._dump_dir: Path | None = None
        self._results: dict[str, Path] = {}

    @property
    def dump_dir(self) -> Path | None:
        return self._dump_dir

    @property
    def results(self) -> dict[str, Path]:
        return self._results.copy()

    @property
    def manifest_metadata(self) -> list[dict]:
        """Return manifest metadata for each extracted artifact."""
        commands = get_profile_commands(self._profile)
        return [
            {
                "id": cmd["id"],
                "output_file": cmd["output_file"],
                "yara_scan": cmd.get("yara_scan", True),
                "ip_extract": cmd.get("ip_extract", False),
                "timeline": cmd.get("timeline", False),
            }
            for cmd in commands
        ]

    def _push_script(self, script_name: str) -> bool:
        """Push a helper script to the device."""
        script_local = Path(__file__).parent / script_name
        if not script_local.exists():
            core.logger.warning(f"Script not found: {script_name}")
            return False
        # Remove existing file to avoid "target is not a directory" error
        serial_arg = f"-s {self._serial} " if self._serial else ""
        core.run_adb(f"{serial_arg}shell rm -f /data/local/tmp/{script_name}", timeout=5)
        local_arg = f'"{script_local}"'
        remote_path = f"/data/local/tmp/{script_name}"
        success, output = core.run_adb(
            f"{serial_arg}push {local_arg} {remote_path}",
            timeout=ADB_TIMEOUT,
        )
        if not success:
            core.logger.warning(f"Failed to push script: {script_name}: {output[:200]}")
            return False
        chmod_ok, chmod_output = core.run_adb(
            f"{serial_arg}shell chmod 700 {remote_path}", timeout=10
        )
        if not chmod_ok:
            core.logger.warning(f"Failed to chmod script: {script_name}: {chmod_output[:200]}")
            return False
        core.logger.info(f"Pushed script: {script_name}")
        return True

    def run(self) -> dict[str, Path]:
        """Execute extraction based on the selected profile. Returns {id: file_path}."""
        self._dump_dir = create_dump_dir()
        self._results = {}

        commands = get_profile_commands(self._profile)
        total = len(commands)
        profile_name = load_manifest()["profiles"][self._profile]["name"]

        self._report_progress(0, f"Profile: {profile_name} — extracting {total} artifacts...")
        ok_count = 0
        fail_count = 0

        for i, cmd in enumerate(commands):
            progress = (i / total) * 100
            self._report_progress(progress, f"[{i+1}/{total}] {cmd['description']}")

            # Push script to device if required
            script_name = cmd.get("script")
            script_ready = self._push_script(script_name) if script_name else False

            serial_arg = f"-s {self._serial} " if self._serial else ""
            success, output = core.run_adb(
                f"{serial_arg}{cmd['adb_cmd']}", timeout=ADB_TIMEOUT
            )

            file_path = self._dump_dir / cmd["output_file"]
            if success and output and not output.startswith("[EXTRACTION FAILED]"):
                file_path.write_text(output, encoding="utf-8", errors="replace")
                self._results[cmd["id"]] = file_path
                ok_count += 1
                size_kb = len(output.encode("utf-8", errors="replace")) / 1024
                core.logger.info(f"Extracted: {cmd['id']} -> {cmd['output_file']} ({size_kb:.1f} KB)")
            else:
                error_msg = output if output else "ADB command returned no data"
                file_path.write_text(
                    f"[EXTRACTION FAILED] {error_msg}\n"
                    f"Command: adb {cmd['adb_cmd']}\n"
                    f"Ensure USB Debugging (Security Settings) is enabled.",
                    encoding="utf-8",
                )
                self._results[cmd["id"]] = file_path
                fail_count += 1
                core.logger.warning(f"Extraction empty: {cmd['id']}")

            if script_name and script_ready:
                remote_path = f"/data/local/tmp/{script_name}"
                serial_arg = f"-s {self._serial} " if self._serial else ""
                cleanup_ok, cleanup_output = core.run_adb(
                    f"{serial_arg}shell rm -f {remote_path}", timeout=10
                )
                if not cleanup_ok:
                    core.logger.warning(
                        f"Remote script cleanup failed: {script_name}: {cleanup_output[:200]}"
                    )

        self._report_progress(100, "Extraction complete.")
        core.logger.success(
            f"Extraction complete. {ok_count} successful, {fail_count} failed "
            f"in {self._dump_dir.name}"
        )
        return self._results

    def _report_progress(self, percent: float, message: str):
        if self._on_progress:
            try:
                self._on_progress(percent, message)
            except Exception:
                pass


def run_extraction(serial: str, profile: str = "deep", on_progress=None) -> dict[str, Path]:
    """Convenience function: run extraction synchronously."""
    extractor = Extractor(serial, profile, on_progress)
    return extractor.run()
