import json
from pathlib import Path

import core
from adapters.base_adapter import BaseAdapter, DeviceInfo, AdapterRegistry


class AndroidAdapter(BaseAdapter):
    """Universal Android adapter — works with ANY Android device via ADB.

    Supports: Samsung, Xiaomi, Google Pixel, OnePlus, Oppo, Vivo,
    Huawei, Motorola, Sony, Nokia, Realme, and all other Android OEMs.
    """

    ANDROID_VIDS = {
        "0x2717": "Xiaomi", "0x18d1": "Google", "0x04e8": "Samsung",
        "0x2a70": "OnePlus", "0x0bb4": "HTC", "0x05c6": "Qualcomm",
        "0x12d1": "Huawei", "0x2207": "Oppo", "0x2717": "Xiaomi",
        "0x0e8d": "MediaTek", "0x2993": "Realme", "0x0fce": "Sony",
        "0x2b4c": "Vivo", "0x0781": "SanDisk", "0x2a45": "Meizu",
    }

    @property
    def name(self) -> str:
        return "Android ADB"

    @property
    def os_type(self) -> str:
        return "android"

    def can_handle(self, serial: str) -> bool:
        success, output = core.run_adb("devices", timeout=5)
        if not success:
            return False
        return serial in output

    def get_device_info(self, serial: str) -> DeviceInfo:
        info = DeviceInfo(serial=serial, os_type="android", adapter_name=self.name)

        def _get(prop, attr):
            ok, val = core.run_adb(f"-s {serial} shell getprop {prop}", timeout=5)
            if ok and val.strip():
                setattr(info, attr, val.strip())

        _get("ro.product.brand", "brand")
        _get("ro.product.model", "model")
        _get("ro.product.name", "product")
        _get("ro.build.version.release", "android_version")
        return info

    def extract(self, serial: str, profile: str, on_progress=None) -> dict[str, str]:
        manifest_path = Path(__file__).resolve().parent.parent / "manifests" / "android_artifacts.json"
        if not manifest_path.exists():
            manifest_path = Path(__file__).resolve().parent.parent / "manifests" / "artifacts.json"

        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)

        profile_cmds = manifest.get("profiles", {}).get(profile, {}).get("commands", [])
        if not profile_cmds:
            core.logger.error(f"Profile '{profile}' not found in manifest")
            return {}

        dump_dir = core.create_dump_dir()
        extracted = {}
        total = len(profile_cmds)

        for i, cmd in enumerate(profile_cmds):
            cmd_id = cmd["id"]
            adb_cmd = cmd["adb_cmd"]
            output_file = cmd["output_file"]
            desc = cmd.get("description", f"Extracting {cmd_id}...")

            if on_progress:
                pct = int((i / total) * 100)
                on_progress(pct, desc)

            core.logger.info(f"[{i+1}/{total}] {desc}")

            if cmd.get("script"):
                script_name = cmd["script"]
                script_src = Path(__file__).resolve().parent.parent / script_name
                if script_src.exists():
                    core.run_adb(f"-s {serial} push {script_src} /data/local/tmp/{script_name}", timeout=30)

            success, output = core.run_adb(f"-s {serial} {adb_cmd}", timeout=60)

            if success and output:
                out_path = dump_dir / output_file
                out_path.write_text(output, encoding="utf-8", errors="replace")
                extracted[cmd_id] = str(out_path)
                core.logger.info(f"Extracted: {cmd_id} -> {output_file} ({len(output)} chars)")
            else:
                core.logger.warning(f"Extraction empty: {cmd_id}")

        if on_progress:
            on_progress(100, f"Extraction complete. {len(extracted)} artifacts.")

        core.logger.info(f"Extraction complete. {len(extracted)} artifacts in {dump_dir.name}")
        return extracted

    def get_profiles(self) -> dict[str, dict]:
        manifest_path = Path(__file__).resolve().parent.parent / "manifests" / "android_artifacts.json"
        if not manifest_path.exists():
            manifest_path = Path(__file__).resolve().parent.parent / "manifests" / "artifacts.json"

        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)

        profiles = {}
        for key, val in manifest.get("profiles", {}).items():
            profiles[key] = {
                "name": val.get("name", key),
                "description": val.get("description", ""),
                "count": len(val.get("commands", [])),
            }
        return profiles


AdapterRegistry.register(AndroidAdapter())
