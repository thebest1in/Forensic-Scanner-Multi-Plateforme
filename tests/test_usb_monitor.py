import time
from unittest.mock import patch

from usb_monitor import USBMonitor


def test_paused_usb_monitor_does_not_probe_adb() -> None:
    monitor = USBMonitor(lambda state, serial: None)
    monitor.pause()
    with patch("core.run_adb") as run_adb:
        monitor.start()
        time.sleep(0.35)
        monitor.stop()
    run_adb.assert_not_called()
