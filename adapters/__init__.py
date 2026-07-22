from adapters.base_adapter import BaseAdapter, DeviceInfo, AdapterRegistry
from adapters.android_adapter import AndroidAdapter

try:
    from adapters.ios_adapter import IOSAdapter
except ImportError:
    pass

try:
    from adapters.linux_docker_adapter import LinuxDockerAdapter
except ImportError:
    pass
