import threading
import time

import core
from core import ANDROID_VIDS, POLL_INTERVAL


class DeviceState:
    DISCONNECTED = "disconnected"
    UNAUTHORIZED = "unauthorized"
    READY = "ready"


class USBMonitor:
    """Polls ADB devices to detect any Android device connection state."""

    def __init__(self, on_state_change):
        self._on_state_change = on_state_change
        self._running = False
        self._thread = None
        self._paused = threading.Event()
        self._current_state = DeviceState.DISCONNECTED
        self._device_serial = None
        self._device_info = {}

    @property
    def state(self):
        return self._current_state

    @property
    def device_serial(self):
        return self._device_serial

    @property
    def device_info(self):
        return self._device_info

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._thread.start()
        core.logger.info("USB monitor started")

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        core.logger.info("USB monitor stopped")

    def pause(self):
        """Pause new ADB probes while an offline archive is being analyzed."""
        self._paused.set()

    def resume(self):
        self._paused.clear()

    def _poll_loop(self):
        while self._running:
            if self._paused.is_set():
                time.sleep(0.25)
                continue
            new_state, serial, info = self._detect_device()
            if new_state != self._current_state:
                self._current_state = new_state
                self._device_serial = serial
                self._device_info = info or {}
                self._on_state_change(new_state, serial)
            time.sleep(POLL_INTERVAL)

    def _detect_device(self) -> tuple[str, str | None, dict | None]:
        success, output = core.run_adb("devices -l", timeout=5)
        if not success or not output:
            return DeviceState.DISCONNECTED, None, None

        lines = output.strip().split("\n")
        if len(lines) <= 1:
            return DeviceState.DISCONNECTED, None, None

        for line in lines[1:]:
            line = line.strip()
            if not line:
                continue

            parts = line.split()
            if len(parts) < 2:
                continue

            serial = parts[0]
            status = parts[1]

            if serial == "List" or serial.startswith("*"):
                continue

            if status == "unauthorized":
                info = self._get_device_info(serial) if serial else {}
                return DeviceState.UNAUTHORIZED, serial, info

            if status == "device":
                info = self._get_device_info(serial) if serial else {}
                return DeviceState.READY, serial, info

        return DeviceState.DISCONNECTED, None, None

    def _get_device_info(self, serial: str) -> dict:
        """Query device properties for display in the GUI."""
        info = {"serial": serial, "brand": "", "model": "", "android": "", "product": ""}

        def _prop(key, target):
            ok, val = core.run_adb(f"-s {serial} shell getprop {key}", timeout=5)
            if ok and val.strip():
                info[target] = val.strip()

        _prop("ro.product.brand", "brand")
        _prop("ro.product.model", "model")
        _prop("ro.build.version.release", "android")
        _prop("ro.product.name", "product")

        return info
