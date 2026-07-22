import logging
import subprocess
import threading
import queue
import time
import sys
import shutil
from pathlib import Path

XIAOMI_VID = "2717"  # legacy — kept for backward compatibility
ANDROID_VIDS = ["2717", "18d1", "04e8", "2a70", "0bb4", "05c6", "12d1", "2207"]
POLL_INTERVAL = 2
ADB_TIMEOUT = 30
DUMP_PREFIX = "dump_forensic"

BASE_DIR = Path(__file__).resolve().parent
RULES_DIR = BASE_DIR / "rules"
YARA_RULES_FILE = RULES_DIR / "poco_rules.yar"
KNOWN_IPS_FILE = RULES_DIR / "known_ips.txt"


def _find_adb() -> str:
    """Locate ADB binary: PATH first, then common Windows install locations."""
    adb_path = shutil.which("adb")
    if adb_path:
        return adb_path
    winget_adb = Path.home() / "AppData/Local/Microsoft/WinGet/Packages"
    if winget_adb.exists():
        for p in winget_adb.rglob("adb.exe"):
            return str(p)
    sdk_adb = Path.home() / "AppData/Local/Android/Sdk/platform-tools/adb.exe"
    if sdk_adb.exists():
        return str(sdk_adb)
    return "adb"


ADB_BINARY = _find_adb()


class ForensicLogger:
    """Thread-safe logger that emits messages to a GUI callback.

    The handler is registered exactly once per process. If a handler already
    exists on the ``forensic`` logger (e.g. from a prior import cycle), the
    constructor reuses it rather than appending a second one.  This prevents
    every log event from being printed twice on the terminal.
    """

    _initialized: bool = False

    def __init__(self):
        self._queue: queue.Queue = queue.Queue()
        self._callback = None
        self._lock = threading.Lock()
        self._logger = logging.getLogger("forensic")
        self._logger.setLevel(logging.DEBUG)
        self._logger.propagate = False
        if not ForensicLogger._initialized:
            handler = logging.StreamHandler()
            handler._forensic_handler = True
            handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
            self._logger.addHandler(handler)
            ForensicLogger._initialized = True

    def set_callback(self, callback):
        with self._lock:
            self._callback = callback

    def _emit(self, level: str, message: str):
        self._logger.log(
            getattr(logging, level.upper(), logging.INFO), message
        )
        with self._lock:
            cb = self._callback
        if cb:
            try:
                cb(level, message)
            except Exception:
                pass

    def info(self, message: str):
        self._emit("INFO", message)

    def warning(self, message: str):
        self._emit("WARNING", message)

    def error(self, message: str):
        self._emit("ERROR", message)

    def success(self, message: str):
        self._emit("SUCCESS", message)


logger = ForensicLogger()


def run_adb(command: str, timeout: int = ADB_TIMEOUT) -> tuple[bool, str]:
    """Execute an ADB command and return (success, output)."""
    full_cmd = f'"{ADB_BINARY}" {command}'
    try:
        result = subprocess.run(
            full_cmd,
            shell=True,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
        )
        output = result.stdout.strip() if result.stdout else ""
        if result.returncode != 0:
            err = (result.stderr or "").strip()
            if err:
                logger.warning(f"ADB stderr: {err}")
            return False, output
        return True, output
    except subprocess.TimeoutExpired:
        logger.error(f"ADB command timed out after {timeout}s: {command}")
        return False, ""
    except FileNotFoundError:
        logger.error("ADB binary not found. Install Android SDK Platform-Tools.")
        return False, ""
    except Exception as e:
        logger.error(f"ADB execution error: {e}")
        return False, ""


def create_dump_dir() -> Path:
    """Create a timestamped extraction directory and return its path."""
    ts = int(time.time())
    dump_dir = BASE_DIR / f"{DUMP_PREFIX}_{ts}"
    dump_dir.mkdir(exist_ok=True)
    logger.info(f"Created extraction directory: {dump_dir.name}")
    return dump_dir


def cleanup_dump_dir(dump_dir: Path) -> bool:
    """Remove the extraction directory and all its contents."""
    import shutil
    try:
        if dump_dir.exists():
            shutil.rmtree(dump_dir)
            logger.info(f"Cleaned up: {dump_dir.name}")
            return True
    except Exception as e:
        logger.error(f"Cleanup failed: {e}")
    return False
