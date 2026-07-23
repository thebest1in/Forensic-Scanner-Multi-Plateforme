import asyncio
import json
from pathlib import Path

import core
from adapters.base_adapter import BaseAdapter, DeviceInfo, AdapterRegistry


def _create_lockdown():
    """Create a pymobiledevice3 lockdown client across API generations."""
    from pymobiledevice3.lockdown import create_using_usbmux

    client = create_using_usbmux()
    if asyncio.iscoroutine(client):
        return asyncio.run(client)
    return client


def _close_lockdown(client) -> None:
    """Close a lockdown client across synchronous/asynchronous APIs."""
    close = getattr(client, "close", None)
    if close is None:
        return
    result = close()
    if asyncio.iscoroutine(result):
        asyncio.run(result)


def _resolve(value):
    return asyncio.run(value) if asyncio.iscoroutine(value) else value


class IOSAdapter(BaseAdapter):
    """iOS device adapter — iPhone & iPad support via pymobiledevice3.

    Supports: All iPhone/iPad models (iOS 12+).
    Requires: pymobiledevice3 (pip install pymobiledevice3)
    Features: Device info, syslog, config profiles, installed apps, backup extraction.
    Note: No jailbreak required for basic forensic triage.
    """

    @property
    def name(self) -> str:
        return "iOS (pymobiledevice3)"

    @property
    def os_type(self) -> str:
        return "ios"

    def can_handle(self, serial: str) -> bool:
        try:
            lockdown = _create_lockdown()
            lockdown.short_info
            _close_lockdown(lockdown)
            return True
        except Exception:
            return False

    def get_device_info(self, serial: str = "") -> DeviceInfo:
        info = DeviceInfo(os_type="ios", adapter_name=self.name)
        try:
            lockdown = _create_lockdown()
            short = lockdown.short_info
            info.serial = short.get("SerialNumber", "")
            info.product = short.get("ProductType", "")  # e.g. iPhone15,2
            info.model = _ios_model_name(info.product)
            info.brand = "Apple"
            info.android_version = short.get("ProductVersion", "")  # iOS version
            _close_lockdown(lockdown)
        except Exception as e:
            core.logger.warning(f"iOS device info failed: {e}")
        return info

    def extract(self, serial: str = "", profile: str = "triage", on_progress=None) -> dict[str, str]:
        manifest_path = Path(__file__).resolve().parent.parent / "manifests" / "ios_artifacts.json"
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)

        profile_data = manifest.get("profiles", {}).get(profile, {})
        # New manifests describe live artifacts; retain support for legacy commands.
        profile_cmds = profile_data.get("commands", profile_data.get("artifacts", []))
        if not profile_cmds:
            core.logger.error(f"iOS profile '{profile}' not found")
            return {}

        dump_dir = core.create_dump_dir()
        extracted = {}
        total = len(profile_cmds)

        for i, cmd in enumerate(profile_cmds):
            cmd_id = cmd.get("id", cmd.get("name", f"artifact_{i+1}"))
            # Live USB mode must never attempt backup-only artifacts.
            if cmd.get("requires_backup", False) or cmd_id in {
                "pairing_status", "sysdiagnose", "ioc_analysis", "mvt_analysis",
                "unified_timeline",
            }:
                core.logger.info(f"Skipped (backup/unavailable in live mode): {cmd_id}")
                continue
            method = cmd.get("method", "lockdown")
            output_file = cmd.get("output_file", f"{cmd_id}.txt")
            desc = cmd.get("description", f"Extracting {cmd_id}...")

            if on_progress:
                pct = int((i / total) * 100)
                on_progress(pct, desc)

            core.logger.info(f"[{i+1}/{total}] {desc}")

            try:
                content = _extract_ios_artifact(cmd_id, method, cmd)
                if content:
                    out_path = dump_dir / output_file
                    out_path.write_text(content, encoding="utf-8", errors="replace")
                    extracted[cmd_id] = out_path
                    core.logger.info(f"Extracted: {cmd_id} -> {output_file}")
                else:
                    core.logger.warning(f"Extraction empty: {cmd_id}")
            except Exception as e:
                core.logger.warning(f"Extraction failed for {cmd_id}: {e}")

        if on_progress:
            on_progress(100, f"iOS extraction complete. {len(extracted)} artifacts.")
        core.logger.info(f"iOS extraction complete. {len(extracted)} artifacts in {dump_dir.name}")
        return extracted

    def get_profiles(self) -> dict[str, dict]:
        manifest_path = Path(__file__).resolve().parent.parent / "manifests" / "ios_artifacts.json"
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


def _ios_model_name(product_type: str) -> str:
    """Map product type identifier to human-readable name."""
    models = {
        "iPhone15,2": "iPhone 14 Pro", "iPhone15,3": "iPhone 14 Pro Max",
        "iPhone16,1": "iPhone 15 Pro", "iPhone16,2": "iPhone 15 Pro Max",
        "iPhone17,1": "iPhone 16 Pro", "iPhone17,2": "iPhone 16 Pro Max",
        "iPhone14,7": "iPhone 14", "iPhone14,8": "iPhone 14 Plus",
        "iPad13,18": "iPad Pro 12.9 (6th gen)", "iPad13,19": "iPad Pro 11 (4th gen)",
    }
    return models.get(product_type, product_type)


def _extract_ios_artifact(cmd_id: str, method: str, cmd: dict) -> str | None:
    """Extract a single iOS forensic artifact."""
    try:
        # Normalize manifest identifiers used by the live profiles.
        cmd_id = {
            "device_information": "device_info",
            "installed_applications": "installed_apps",
            "configuration_profiles": "config_profiles",
        }.get(cmd_id, cmd_id)
        from pymobiledevice3.services.mobile_config import MobileConfigService
        from pymobiledevice3.services.installation_proxy import InstallationProxyService

        lockdown = _create_lockdown()

        if cmd_id == "device_info":
            info = lockdown.short_info
            lines = [f"{k}: {v}" for k, v in info.items()]
            _close_lockdown(lockdown)
            return "\n".join(lines)

        if cmd_id == "installed_apps":
            try:
                service = InstallationProxyService(lockdown=lockdown)
                apps = _resolve(service.get_apps(application_type="Any"))
                lines = []
                for bundle_id, app_info in sorted(apps.items()):
                    name = app_info.get("CFBundleDisplayName", app_info.get("CFBundleName", ""))
                    version = app_info.get("CFBundleShortVersionString", "")
                    lines.append(f"{bundle_id} | {name} | v{version}")
                _close_lockdown(lockdown)
                return "\n".join(lines)
            except Exception:
                _close_lockdown(lockdown)
                return None

        if cmd_id == "config_profiles":
            try:
                service = MobileConfigService(lockdown=lockdown)
                profiles = _resolve(service.get_profile_list())
                lines = []
                for p in profiles:
                    pid = p.get("PayloadIdentifier", "unknown")
                    pname = p.get("PayloadDisplayName", "unknown")
                    ptype = p.get("PayloadType", "unknown")
                    lines.append(f"{pid} | {pname} | {ptype}")
                _close_lockdown(lockdown)
                return "\n".join(lines)
            except Exception:
                _close_lockdown(lockdown)
                return None

        if cmd_id == "syslog":
            try:
                from pymobiledevice3.services.syslog import SyslogService
                syslog = SyslogService(lockdown=lockdown)
                lines = []
                for i, entry in enumerate(syslog.watch()):
                    lines.append(str(entry))
                    if i > 2000:
                        break
                _close_lockdown(lockdown)
                return "\n".join(lines[-2000:])
            except Exception:
                _close_lockdown(lockdown)
                return None

        _close_lockdown(lockdown)
        return None

    except Exception as e:
        core.logger.warning(f"iOS extraction error ({cmd_id}): {e}")
        return None


AdapterRegistry.register(IOSAdapter())
