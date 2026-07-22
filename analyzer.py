import re
import json
import time
import csv
import ipaddress
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

from core import logger, YARA_RULES_FILE, KNOWN_IPS_FILE, BASE_DIR
from yara_context import classify_yara_match, representative_evidence
from yara_diagnostics import collect_match_evidence

try:
    from heuristics import analyze_permissions, HeuristicResult
    HEURISTICS_AVAILABLE = True
except ImportError:
    HEURISTICS_AVAILABLE = False

try:
    from history_db import (
        build_scan_record, record_scan, compute_delta,
        init_db, ScanRecord,
    )
    HISTORY_AVAILABLE = True
except ImportError:
    HISTORY_AVAILABLE = False

try:
    from mvt_bridge import scan_ios_backup, scan_android_dump, check_mvt_available
    MVT_AVAILABLE = True
except ImportError:
    MVT_AVAILABLE = False

try:
    from aleapp_bridge import run_aleapp, parse_aleapp_offline, check_aleapp_available
    ALEAPP_AVAILABLE = True
except ImportError:
    ALEAPP_AVAILABLE = False

try:
    from capa_bridge import scan_apk, scan_directory, check_capa_available
    CAPA_AVAILABLE = True
except ImportError:
    CAPA_AVAILABLE = False

try:
    from apkid_bridge import APKiDBridge
    APKID_AVAILABLE = True
except ImportError:
    APKID_AVAILABLE = False

try:
    from quark_bridge import QuarkBridge
    QUARK_AVAILABLE = True
except ImportError:
    QUARK_AVAILABLE = False

try:
    from intel_bridge import IntelBridge
    INTEL_AVAILABLE = True
except ImportError:
    INTEL_AVAILABLE = False

try:
    from entropy_bridge import EntropyBridge
    ENTROPY_AVAILABLE = True
except ImportError:
    ENTROPY_AVAILABLE = False

try:
    from browser_forensics_bridge import BrowserForensicsBridge
    BROWSER_FORENSICS_AVAILABLE = True
except ImportError:
    BROWSER_FORENSICS_AVAILABLE = False

try:
    from correlation_engine import CorrelationEngine
    CORRELATION_AVAILABLE = True
except ImportError:
    CORRELATION_AVAILABLE = False


# ============================================================
# LOG FILTER GATE — Strip benign noise before YARA scanning
# ============================================================

_NOISE_PATTERNS = [
    re.compile(r".*Binder.*$", re.MULTILINE),
    re.compile(r".*Choreographer.*Skipped.*$", re.MULTILINE),
    re.compile(r".*InputMethodManager.*$", re.MULTILINE),
    re.compile(r".*SurfaceFlinger.*$", re.MULTILINE),
    re.compile(r".*ActivityThread.*$", re.MULTILINE),
    re.compile(r".*WindowManager.*$", re.MULTILINE),
    re.compile(r".*PackageManager.*$", re.MULTILINE),
    re.compile(r".*BluetoothAdapter.*$", re.MULTILINE),
    re.compile(r".*ConnectivityService.*WifiStateMachine.*$", re.MULTILINE),
    re.compile(r".*NetdConnector.*$", re.MULTILINE),
    re.compile(r".*BatteryService.*level=.*$", re.MULTILINE),
    re.compile(r".*MediaSessionService.*$", re.MULTILINE),
    re.compile(r".*AlarmManagerService.*wakeup.*$", re.MULTILINE),
    re.compile(r".*JobSchedulerService.*$", re.MULTILINE),
    re.compile(r".*DropBoxManagerService.*$", re.MULTILINE),
    re.compile(r".*PowerManagerService.*release.*$", re.MULTILINE),
    re.compile(r".*Vibration.*$", re.MULTILINE),
    re.compile(r".*sensor.*heart_rate.*$", re.MULTILINE),
    re.compile(r".*thermal.*throttl.*$", re.MULTILINE),
    re.compile(r".*telephony.*signal_strength.*$", re.MULTILINE),
]


def filter_noise(content: str) -> str:
    """Remove benign OS noise from log content. Returns filtered text."""
    filtered = content
    for pattern in _NOISE_PATTERNS:
        filtered = pattern.sub("", filtered)
    original_size = len(content.encode("utf-8", errors="replace"))
    filtered_size = len(filtered.encode("utf-8", errors="replace"))
    if original_size > 0:
        reduction = (1 - filtered_size / original_size) * 100
        if reduction > 1:
            logger.info(f"Log filter: {reduction:.0f}% noise removed ({original_size//1024}KB -> {filtered_size//1024}KB)")
    return filtered


# ============================================================
# CORE ANALYSIS TYPES
# ============================================================

class ThreatVerdict:
    CLEAN = "CLEAN"
    SUSPICIOUS = "SUSPICIOUS"
    CRITICAL = "CRITICAL"


class AnalysisResult:
    def __init__(self):
        self.verdict = ThreatVerdict.CLEAN
        self.matched_rules: list[dict] = []
        self.suspicious_ips: list[dict] = []
        self.vt_results: list[dict] = []
        self.scanned_files: int = 0
        self.summary: str = ""
        self.timestamp: str = ""
        self.device_serial: str = ""
        self.filter_stats: dict = {}
        self.heuristic_result: dict | None = None
        self.history_delta: dict | None = None
        self.pcap_results: dict | None = None
        self.mvt_results: list[dict] = []
        self.aleapp_results: list[dict] = []
        self.capa_results: list[dict] = []
        self.apkid_results: list[dict] = []
        self.quark_results: list[dict] = []
        self.otx_results: list[dict] = []
        self.intel_results: list[dict] = []
        self.entropy_results: list[dict] = []
        self.browser_results: list[dict] = []
        self.correlation_result: dict | None = None
        self.composite_risk_score: int = 0
        self.composite_risk_level: str = "CLEAN"
        self.verdict_reasons: list[str] = []
        self.indexed_files: int = 0
        self.tool_status: dict[str, str] = {}  # {phase: "ok"|"error"|"skipped"|"disabled"}

    def to_dict(self) -> dict:
        from version import APP_NAME, REPORT_SCHEMA_VERSION, VERSION
        d = {
            "report_version": REPORT_SCHEMA_VERSION,
            "tool": f"{APP_NAME} v{VERSION}",
            "timestamp": self.timestamp,
            "device_serial": self.device_serial,
            "verdict": self.verdict,
            "scanned_files": self.scanned_files,
            "log_filter_stats": self.filter_stats,
            "yara_matches": self.matched_rules,
            "suspicious_ips": sorted(set(self.suspicious_ips)),
            "virustotal_lookups": self.vt_results,
            "heuristics": self.heuristic_result,
            "history_delta": self.history_delta,
            "pcap_analysis": self.pcap_results,
            "mvt_analysis": self.mvt_results,
            "aleapp_analysis": self.aleapp_results,
            "capa_analysis": self.capa_results,
            "apkid_analysis": self.apkid_results,
            "quark_analysis": self.quark_results,
            "otx_analysis": self.otx_results,
            "intel_analysis": self.intel_results,
            "entropy_analysis": self.entropy_results,
            "browser_forensics": self.browser_results,
            "correlation": self.correlation_result,
            "composite_risk_score": self.composite_risk_score,
            "composite_risk_level": self.composite_risk_level,
            "verdict_reasons": self.verdict_reasons,
            "indexed_files": self.indexed_files,
            "tool_status": self.tool_status,
            "summary": self.summary,
        }
        return d

    def to_json(self, indent=2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)


# ============================================================
# IOC & YARA HELPERS
# ============================================================

_IP_REGEX = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b"
)

_PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("0.0.0.0/8"),
]


def _is_private_ip(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _PRIVATE_RANGES)
    except ValueError:
        return True


def _load_known_ips() -> set[str]:
    known = set()
    if not KNOWN_IPS_FILE.exists():
        logger.warning(f"IOC file not found: {KNOWN_IPS_FILE.name}")
        return known
    for line in KNOWN_IPS_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            known.add(line)
    logger.info(f"Loaded {len(known)} known malicious IPs")
    return known


def _compile_yara_rules():
    if not YARA_AVAILABLE:
        logger.error("yara-python not installed. YARA scanning disabled.")
        return None
    if not YARA_RULES_FILE.exists():
        logger.error(f"YARA rules file not found: {YARA_RULES_FILE}")
        return None
    try:
        rules = yara.compile(filepath=str(YARA_RULES_FILE))
        logger.info(f"YARA rules compiled: {YARA_RULES_FILE.name}")
        return rules
    except yara.SyntaxError as e:
        logger.error(f"YARA syntax error: {e}")
        return None
    except Exception as e:
        logger.error(f"YARA compilation failed: {e}")
        return None


def _lookup_ip_virustotal(ip: str) -> dict:
    if not REQUESTS_AVAILABLE:
        return {"ip": ip, "status": "requests not installed"}
    try:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            return {
                "ip": ip,
                "malicious_detections": malicious,
                "suspicious_detections": suspicious,
                "total_engines": sum(stats.values()),
                "country": data.get("country", "Unknown"),
                "as_owner": data.get("as_owner", "Unknown"),
            }
        elif resp.status_code == 404:
            return {"ip": ip, "status": "not_found"}
        elif resp.status_code == 429:
            return {"ip": ip, "status": "rate_limited"}
        else:
            return {"ip": ip, "status": f"error_{resp.status_code}"}
    except Exception as e:
        return {"ip": ip, "status": f"error: {str(e)}"}


# ============================================================
# MAIN ANALYSIS ENGINE
# ============================================================

def analyze(
    extracted_files: dict[str, Path],
    device_serial: str = "",
    check_virustotal: bool = False,
    manifest_metadata: list[dict] | None = None,
    on_progress=None,
    dump_dir: Path | None = None,
    run_mvt: bool = False,
    run_aleapp: bool = False,
    run_capa: bool = False,
    run_apkid: bool = False,
    run_quark: bool = False,
    run_intel: bool = False,
    run_entropy: bool = False,
    run_browser: bool = False,
    run_correlation: bool = True,
    device_type: str = "android",
    adapter_info: dict | None = None,
) -> AnalysisResult:
    """Run full threat analysis with optional log pre-filtering and advanced tools.

    Args:
        extracted_files: Map of artifact names to file paths
        device_serial: Device serial number
        check_virustotal: Enable VirusTotal IP lookups
        manifest_metadata: Optional manifest metadata
        on_progress: Progress callback(percent, message)
        run_mvt: Enable MVT spyware IOC scanning
        run_aleapp: Enable ALEAPP deep artifact parsing
        run_capa: Enable Mandiant capa static analysis
        run_apkid: Enable APKiD packer/obfuscation detection
        run_quark: Enable Quark-Engine behavioral rule scoring
        run_intel: Enable OTX + AbuseIPDB live IP intelligence
        run_entropy: Enable Shannon entropy analysis
        run_browser: Enable Chrome/WebView browser forensics
        run_correlation: Enable cross-tool correlation (default: True)
        device_type: "android" or "ios"
        adapter_info: Optional adapter metadata
    """
    result = AnalysisResult()
    result.timestamp = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    result.device_serial = device_serial
    result.indexed_files = len(extracted_files)
    known_ips = _load_known_ips()
    yara_rules = _compile_yara_rules()

    YARA_SKIP_PREFIXES = ("temp_anr_", "anr_2026")
    YARA_SKIP_SUFFIXES = (".db", ".bin", ".dat", ".gz", ".img", ".so", ".apk", ".zip")
    YARA_SKIP_NAMES = {"dumpstate_board.txt", "cameraopt.txt", "failkeeper.db",
                        "HangChart.txt", "LocalHangRecord.txt",
                        "LocalSubSystemRestartRecord.txt", "LocalVMRebootRecord.txt",
                        "RebootChart.txt", "SubSystemChart.txt"}

    def _should_skip_yara(fp: Path) -> bool:
        if fp.name in YARA_SKIP_NAMES:
            return True
        if any(fp.name.startswith(p) for p in YARA_SKIP_PREFIXES):
            return True
        if fp.suffix.lower() in YARA_SKIP_SUFFIXES:
            return True
        return False

    all_files = list(extracted_files.values())
    files_to_scan = [f for f in all_files if not _should_skip_yara(f)]
    skipped_count = len(all_files) - len(files_to_scan)
    if skipped_count:
        logger.info(f"YARA: {skipped_count} junk/binary files skipped, {len(files_to_scan)} to scan")
    result.scanned_files = len(files_to_scan)
    total_steps = max(len(files_to_scan), 1)

    total_original = 0
    total_filtered = 0
    REPORT_EVERY = 50

    for i, file_path in enumerate(files_to_scan):
        if i == 0 or (i + 1) % REPORT_EVERY == 0 or (i + 1) == len(files_to_scan):
            progress = 5 + (i / total_steps) * 70
            _report(on_progress, progress,
                    f"YARA scan: {i+1}/{len(files_to_scan)} files ({file_path.name})")
        if i == 0:
            _report(on_progress, 5, f"YARA scanning {len(files_to_scan)} files...")

        if not file_path.exists():
            logger.warning(f"File not found for scanning: {file_path}")
            continue

        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            logger.error(f"Cannot read {file_path.name}: {e}")
            continue

        # Apply noise filter to log-type files
        is_log_file = file_path.suffix in (".log",) or "log" in file_path.stem.lower()
        if is_log_file:
            original_size = len(content.encode("utf-8", errors="replace"))
            content = filter_noise(content)
            filtered_size = len(content.encode("utf-8", errors="replace"))
            total_original += original_size
            total_filtered += filtered_size

        if yara_rules:
            try:
                matches = yara_rules.match(data=content)
                scanned_data = content.encode("utf-8", errors="replace") if matches else b""
                for match in matches:
                    all_evidence = collect_match_evidence(match, file_path, scanned_data)
                    assessment = classify_yara_match(
                        match.rule,
                        dict(getattr(match, "meta", {})),
                        file_path,
                        all_evidence,
                    )
                    evidence = representative_evidence(all_evidence)
                    for item in evidence:
                        item["confidence"] = assessment["confidence"]
                    rule_info = {
                        "rule": match.rule,
                        "namespace": getattr(match, "namespace", "default"),
                        "tags": list(match.tags),
                        "file": file_path.name,
                        "artifact_path": str(file_path.resolve()),
                        "meta": getattr(match, "meta", {}),
                        "classification": assessment["classification"],
                        "confidence": assessment["confidence"],
                        "authoritative": assessment["authoritative"],
                        "context_reason": assessment["reason"],
                        "evidence": evidence,
                        "total_string_matches": len(all_evidence),
                    }
                    result.matched_rules.append(rule_info)
                    logger.warning(
                        f"YARA match: {match.rule} in {file_path.name} "
                        f"({assessment['classification']}, confidence="
                        f"{assessment['confidence']:.2f})"
                    )
            except Exception as e:
                logger.error(f"YARA scan error on {file_path.name}: {e}")

        found_ips = set(_IP_REGEX.findall(content))
        external_ips = {ip for ip in found_ips if not _is_private_ip(ip)}
        hits = external_ips & known_ips
        if hits:
            result.suspicious_ips.extend(sorted(hits))
            for ip in sorted(hits):
                logger.warning(f"Malicious IP found: {ip} in {file_path.name}")

    result.filter_stats = {
        "total_original_bytes": total_original,
        "total_filtered_bytes": total_filtered,
        "noise_reduction_pct": round(
            (1 - total_filtered / total_original) * 100, 1
        ) if total_original > 0 else 0,
    }

    _report(on_progress, 78, "Cross-referencing IOCs...")

    if check_virustotal and result.suspicious_ips:
        _report(on_progress, 82, "Looking up IPs on VirusTotal...")
        unique_ips = list(set(result.suspicious_ips))[:5]
        for ip in unique_ips:
            vt_result = _lookup_ip_virustotal(ip)
            result.vt_results.append(vt_result)
            logger.info(f"VT lookup: {ip} -> {vt_result.get('status', 'ok')}")

    # Phase 2: Heuristic permission analysis
    if HEURISTICS_AVAILABLE:
        _report(on_progress, 85, "Running heuristic permission analysis...")
        try:
            h_result = analyze_permissions(extracted_files, on_progress=on_progress)
            result.heuristic_result = h_result.to_dict()
            if h_result.risk_level in ("CRITICAL", "SUSPICIOUS"):
                logger.warning(f"Heuristic risk: {h_result.risk_level} (score={h_result.risk_score})")
        except Exception as e:
            logger.warning(f"Heuristic analysis failed: {e}")

    # Phase 3: History delta computation
    if HISTORY_AVAILABLE and device_serial:
        _report(on_progress, 88, "Computing scan delta...")
        try:
            init_db()
            scan_record = build_scan_record(
                device_serial=device_serial,
                verdict="PENDING",
                extracted_files=extracted_files,
                yara_matches=result.matched_rules,
                suspicious_ips=result.suspicious_ips,
                risk_score=result.heuristic_result.get("risk_score", 0) if result.heuristic_result else 0,
            )
            delta = compute_delta(scan_record, device_serial)
            result.history_delta = delta
            if delta.get("anomalies"):
                logger.warning(f"Delta anomalies: {len(delta['anomalies'])}")
        except Exception as e:
            logger.warning(f"History delta failed: {e}")

    # Phases 4-11: Run independent tools concurrently for speed
    _report(on_progress, 88, "Running analysis tools concurrently...")
    tool_futures = {}

    def _run_mvt():
        if not run_mvt:
            return ("mvt", "disabled", [])
        dump_path = extracted_files.get("dump")
        mvt_path = extracted_files.get("mvt_backup")
        if not (
            (dump_path is not None and dump_path.exists())
            or (mvt_path is not None and mvt_path.exists())
        ):
            return ("mvt", "skipped_no_input", [])
        if not MVT_AVAILABLE or not check_mvt_available():
            return ("mvt", "unavailable", [])
        try:
            if device_type == "ios" and adapter_info:
                if mvt_path and mvt_path.exists():
                    mvt_output = mvt_path / "mvt_output"
                    mvt_result = scan_ios_backup(mvt_path, mvt_output)
                    return ("mvt", "ok", [mvt_result.to_dict()])
            elif dump_path and dump_path.exists():
                mvt_output = dump_path / "mvt_output"
                mvt_result = scan_android_dump(dump_path, mvt_output)
                return ("mvt", "ok", [mvt_result.to_dict()])
            return ("mvt", "ok", [])
        except Exception as e:
            logger.warning(f"MVT analysis failed: {e}")
            return ("mvt", "error", [])

    def _run_aleapp():
        if not run_aleapp:
            return ("aleapp", "disabled", [])
        aleapp_output = extracted_files.get("aleapp_output")
        if not aleapp_output or not aleapp_output.exists():
            aleapp_output = extracted_files.get("dump")
        if not aleapp_output or not aleapp_output.exists():
            aleapp_output = dump_dir
        if not aleapp_output or not aleapp_output.exists() or not aleapp_output.is_dir():
            return ("aleapp", "skipped_no_input", [])
        if not ALEAPP_AVAILABLE or not check_aleapp_available():
            return ("aleapp", "unavailable", [])
        try:
            aleapp_result = parse_aleapp_offline(aleapp_output)
            return ("aleapp", "ok", [aleapp_result.to_dict()])
        except Exception as e:
            logger.warning(f"ALEAPP analysis failed: {e}")
            return ("aleapp", "error", [])

    def _run_capa():
        if not run_capa:
            return ("capa", "disabled", [])
        apk_path = extracted_files.get("base_apk")
        dump_path = extracted_files.get("dump")
        if not (
            (apk_path is not None and apk_path.exists())
            or (dump_path is not None and dump_path.exists())
        ):
            return ("capa", "skipped_no_input", [])
        if not CAPA_AVAILABLE or not check_capa_available():
            return ("capa", "unavailable", [])
        try:
            if apk_path and apk_path.exists() and apk_path.suffix == ".apk":
                capa_result = scan_apk(apk_path)
                if capa_result:
                    return ("capa", "ok", [capa_result.to_dict()])
            else:
                if dump_path and dump_path.exists():
                    capa_result = scan_directory(dump_path)
                    if capa_result:
                        return ("capa", "ok", [capa_result.to_dict()])
            return ("capa", "ok", [])
        except Exception as e:
            logger.warning(f"Capa analysis failed: {e}")
            return ("capa", "error", [])

    def _run_apkid():
        if not run_apkid:
            return ("apkid", "disabled", [])
        apk_files = [f for f in extracted_files.values() if f.suffix == ".apk"]
        dump_path = extracted_files.get("dump")
        if not apk_files and dump_path and dump_path.exists():
            apk_files = list(dump_path.rglob("*.apk"))
        if not apk_files:
            return ("apkid", "skipped_no_input", [])
        if not APKID_AVAILABLE or not APKiDBridge.check_apkid_available():
            return ("apkid", "unavailable", [])
        try:
            apkid = APKiDBridge(serial=device_serial)
            results = []
            for apk in apk_files:
                results.append(apkid.scan_apk(apk).to_dict())
            return ("apkid", "ok", results)
        except Exception as e:
            logger.warning(f"APKiD analysis failed: {e}")
            return ("apkid", "error", [])

    def _run_quark():
        if not run_quark:
            return ("quark", "disabled", [])
        apk_files = [f for f in extracted_files.values() if f.suffix == ".apk"]
        dump_path = extracted_files.get("dump")
        if not apk_files and dump_path and dump_path.exists():
            apk_files = list(dump_path.rglob("*.apk"))
        if not apk_files:
            return ("quark", "skipped_no_input", [])
        if not QUARK_AVAILABLE or not QuarkBridge.check_quark_available():
            return ("quark", "unavailable", [])
        try:
            quark = QuarkBridge()
            results = []
            for apk in apk_files:
                results.append(quark.scan_apk(apk).to_dict())
            return ("quark", "ok", results)
        except Exception as e:
            logger.warning(f"Quark analysis failed: {e}")
            return ("quark", "error", [])

    def _run_intel():
        if not run_intel:
            return ("intel", "disabled", [])
        all_ips = set(result.suspicious_ips)
        for pcap_ip in (result.pcap_results or {}).get("c2_hits", []):
            if isinstance(pcap_ip, dict):
                all_ips.add(pcap_ip.get("source_ip", ""))
        all_ips.discard("")
        if not all_ips:
            return ("intel", "skipped_no_input", [])
        if not INTEL_AVAILABLE:
            return ("intel", "unavailable", [])
        try:
            intel = IntelBridge()
            if not intel.check_available():
                return ("intel", "unavailable", [])
            intel_results = intel.lookup_ips(list(all_ips)[:20])
            return ("intel", "ok", [r.to_dict() for r in intel_results])
        except Exception as e:
            logger.warning(f"Intel lookup failed: {e}")
            return ("intel", "error", [])

    def _run_entropy():
        if not run_entropy:
            return ("entropy", "disabled", [])
        if not ENTROPY_AVAILABLE:
            return ("entropy", "unavailable", [])
        try:
            entropy = EntropyBridge()
            ENTROPY_MAX_SIZE = 5 * 1024 * 1024
            ENTROPY_EXTENSIONS = (".log", ".txt", ".csv", ".xml", ".json", "")
            ent_files = [v for v in extracted_files.values()
                         if v.exists() and v.stat().st_size <= ENTROPY_MAX_SIZE
                         and v.suffix.lower() in ENTROPY_EXTENSIONS]
            if not ent_files:
                return ("entropy", "skipped_no_input", [])
            ent_results = []
            for fp in ent_files:
                ent_results.append(entropy.analyze_file(fp))
            flagged = [r.to_dict() for r in ent_results if r.exfil_risk or r.obfuscation_risk]
            return ("entropy", "ok", flagged)
        except Exception as e:
            logger.warning(f"Entropy analysis failed: {e}")
            return ("entropy", "error", [])

    def _run_browser():
        if not run_browser:
            return ("browser", "disabled", [])
        dump_path = extracted_files.get("dump")
        if dump_path is None or not dump_path.exists():
            return ("browser", "skipped_no_input", [])
        if not BROWSER_FORENSICS_AVAILABLE:
            return ("browser", "unavailable", [])
        try:
            browser = BrowserForensicsBridge()
            if not browser.check_available():
                return ("browser", "unavailable", [])
            browser_result = browser.scan_dump(dump_path)
            if browser_result.total_visits > 0:
                return ("browser", "ok", [browser_result.to_dict()])
            return ("browser", "ok", [])
        except Exception as e:
            logger.warning(f"Browser forensics failed: {e}")
            return ("browser", "error", [])

    # Dispatch all tool phases concurrently
    tool_runners = [
        _run_mvt, _run_aleapp, _run_capa, _run_apkid,
        _run_quark, _run_intel, _run_entropy, _run_browser,
    ]
    num_workers = min(len(tool_runners), 6)
    with ThreadPoolExecutor(max_workers=num_workers) as executor:
        futures = {executor.submit(fn): fn.__name__ for fn in tool_runners}
        completed = 0
        for future in as_completed(futures):
            completed += 1
            try:
                tool_name, status, data = future.result()
                result.tool_status[tool_name] = status
                if tool_name == "mvt":
                    result.mvt_results = data
                elif tool_name == "aleapp":
                    result.aleapp_results = data
                elif tool_name == "capa":
                    result.capa_results = data
                elif tool_name == "apkid":
                    result.apkid_results = data
                elif tool_name == "quark":
                    result.quark_results = data
                elif tool_name == "intel":
                    result.intel_results = data
                elif tool_name == "entropy":
                    result.entropy_results = data
                elif tool_name == "browser":
                    result.browser_results = data
                pct = 88 + int((completed / len(tool_runners)) * 8)
                _report(on_progress, pct, f"Tools: {completed}/{len(tool_runners)} done ({tool_name})")
                if data:
                    logger.warning(f"{tool_name}: {len(data)} findings")
            except Exception as e:
                logger.warning(f"Tool future failed: {e}")

    # Phase 12: Cross-tool correlation
    if run_correlation and CORRELATION_AVAILABLE:
        _report(on_progress, 99, "Running cross-tool correlation...")
        try:
            correlator = CorrelationEngine()
            corr_result = correlator.correlate(result)
            result.correlation_result = corr_result.to_dict()
            result.tool_status["correlation"] = "ok"
            if corr_result.total_correlations > 0:
                logger.warning(
                    f"Correlation: {corr_result.total_correlations} events "
                    f"({corr_result.critical_count} critical)"
                )
        except Exception as e:
            result.tool_status["correlation"] = "error"
            logger.warning(f"Correlation analysis failed: {e}")
    elif run_correlation:
        result.tool_status["correlation"] = "unavailable"

    _report(on_progress, 99, "Computing composite risk score...")
    result.composite_risk_score, result.composite_risk_level = _compute_composite_risk(result)
    result.verdict = _compute_verdict(result)
    result.verdict_reasons = _explain_verdict(result)
    result.summary = _build_summary(result)

    # Record scan to history DB
    if HISTORY_AVAILABLE and device_serial:
        try:
            record = build_scan_record(
                device_serial=device_serial,
                verdict=result.verdict,
                extracted_files=extracted_files,
                yara_matches=result.matched_rules,
                suspicious_ips=result.suspicious_ips,
                risk_score=result.heuristic_result.get("risk_score", 0) if result.heuristic_result else 0,
            )
            record_scan(record)
        except Exception as e:
            logger.warning(f"Failed to record scan: {e}")

    # Fill tool_status for tools that were explicitly disabled
    for tool, enabled in [("mvt", run_mvt), ("aleapp", run_aleapp), ("capa", run_capa),
                          ("apkid", run_apkid), ("quark", run_quark), ("intel", run_intel),
                          ("entropy", run_entropy), ("browser", run_browser)]:
        if tool not in result.tool_status:
            result.tool_status[tool] = "ok" if enabled else "disabled"

    _report(on_progress, 100, "Analysis complete.")
    logger.success(f"Analysis verdict: {result.verdict}")
    return result


def save_report(result: AnalysisResult, dump_dir: Path) -> Path:
    """Save the analysis report as JSON."""
    report_path = dump_dir / "forensic_report.json"
    report_path.write_text(result.to_json(), encoding="utf-8")
    logger.success(f"Report saved: {report_path.name}")
    return report_path


# ============================================================
# COMPOSITE RISK SCORE
# ============================================================

# YARA severity → point contribution
_YARA_SEVERITY_POINTS = {
    "CRITICAL": 35,
    "HIGH": 22,
    "MEDIUM": 12,
    "LOW": 5,
}


def _compute_composite_risk(result: AnalysisResult) -> tuple[int, str]:
    """Combine all analysis signals into a single 0-100 risk score.

    Weights:
      - YARA rule matches:         up to 35 points
      - Heuristic permission score: up to 25 points (scaled from 0-100)
      - MVT/APKiD/Quark/capa:     up to 20 points
      - IOC/network intel:         up to 10 points
      - Entropy/browser/corr:      up to 10 points

    When tools fail to run (error/unavailable), their weight is redistributed
    proportionally across the remaining categories so a crashed analyzer never
    scores 0 (= clean) — it simply doesn't count.

    Returns (score, level) where level is CLEAN/LOW_RISK/SUSPICIOUS/CRITICAL.
    """
    ts = result.tool_status

    # --- YARA matches (35 pts max) --- accumulates corroboration
    yara_points = []
    contextual_score = 0
    for rule in result.matched_rules:
        tags = {t.lower() for t in rule.get("tags", [])}
        name = rule.get("rule", "").lower()
        critical_tags = {"pegasus", "zero_click", "novispy", "finspy",
                         "dendroid", "hackingteam", "sandrorat", "reverse_shell",
                         "stalkerware", "disguised_package", "spyware",
                         "credential_theft", "data_exfil"}
        high_tags = {"battery_drain", "root_evasion"}
        if tags & critical_tags or any(ct in name for ct in critical_tags):
            severity = "CRITICAL"
        elif tags & high_tags:
            severity = "HIGH"
        else:
            severity = "MEDIUM"
        points = _YARA_SEVERITY_POINTS.get(severity, 5)
        if rule.get("authoritative", True):
            yara_points.append(points)
        else:
            confidence = max(0.0, min(float(rule.get("confidence", 0.0)), 1.0))
            contextual_score += int(points * confidence * 0.25)
    yara_points.sort(reverse=True)
    if yara_points:
        yara_score = yara_points[0]
        for extra in yara_points[1:]:
            yara_score += int(extra * 0.3)
        yara_score = min(yara_score, 35)
    else:
        yara_score = 0
    yara_score = min(yara_score + contextual_score, 35)

    # --- Heuristic permission score (25 pts max) --- never skipped
    h_pts = 0
    if result.heuristic_result:
        h_score = result.heuristic_result.get("risk_score", 0)
        h_pts = min(int(h_score * 0.25), 25)

    # --- Tool bucket (20 pts max): MVT/APKiD/Quark/capa/ALEAPP ---
    tool_raw = 0
    tool_ok = ts.get("mvt") == "ok" or ts.get("apkid") == "ok" or ts.get("quark") == "ok" or ts.get("capa") == "ok" or ts.get("aleapp") == "ok"
    for mvt in result.mvt_results:
        if mvt.get("threat_level") in ("critical", "high"):
            tool_raw = max(tool_raw, 10)
        elif mvt.get("threat_level") == "medium":
            tool_raw = max(tool_raw, 5)
    for capa in result.capa_results:
        mal_caps = capa.get("malicious_capabilities", [])
        if any(c.get("severity") == "critical" for c in mal_caps):
            tool_raw = max(tool_raw, 10)
        elif mal_caps:
            tool_raw = max(tool_raw, 5)
    for apkid in result.apkid_results:
        if apkid.get("threat_level") == "CRITICAL":
            tool_raw = max(tool_raw, 8)
        elif apkid.get("packers_found") or apkid.get("anti_analysis"):
            tool_raw = max(tool_raw, 4)
    for quark in result.quark_results:
        if quark.get("threat_level") == "CRITICAL":
            tool_raw = max(tool_raw, 8)
        elif quark.get("threat_level") == "SUSPICIOUS":
            tool_raw = max(tool_raw, 4)
    for aleapp in result.aleapp_results:
        aleapp_severity = aleapp.get("severity", "CLEAN")
        if aleapp_severity == "CRITICAL":
            tool_raw = max(tool_raw, 15)
        elif aleapp_severity == "SUSPICIOUS":
            tool_raw = max(tool_raw, 8)
    tool_pts = min(tool_raw, 20)

    # --- IOC/network intel (10 pts max) ---
    intel_raw = 0
    if result.suspicious_ips:
        intel_raw = min(len(result.suspicious_ips) * 2, 6)
    for intel in result.intel_results:
        if intel.get("c2_match"):
            intel_raw = max(intel_raw, 10)
        elif intel.get("is_malicious"):
            intel_raw = max(intel_raw, 6)
    if result.pcap_results and result.pcap_results.get("c2_hits"):
        intel_raw = max(intel_raw, 8)
    intel_pts = min(intel_raw, 10)

    # --- Entropy/browser/correlation (10 pts max) ---
    extra_raw = 0
    for ent in result.entropy_results:
        if ent.get("exfil_risk") and ent.get("obfuscation_risk"):
            extra_raw = max(extra_raw, 8)
        elif ent.get("exfil_risk") or ent.get("obfuscation_risk"):
            extra_raw = max(extra_raw, 4)
    for browser in result.browser_results:
        sus_count = len(browser.get("suspicious_visits", []))
        if sus_count >= 5:
            extra_raw = max(extra_raw, 8)
        elif sus_count > 0:
            extra_raw = max(extra_raw, 3)
    corr = result.correlation_result or {}
    if corr.get("critical_count", 0) >= 2:
        extra_raw = max(extra_raw, 10)
    elif corr.get("high_count", 0) >= 2:
        extra_raw = max(extra_raw, 6)
    extra_pts = min(extra_raw, 10)

    # --- Renormalize when tools fail ---
    # Max possible: 35 + 25 + 20 + 10 + 10 = 100
    # If tool bucket errored/skipped, redistribute its 20pts proportionally
    tool_bucket_max = 20
    if not tool_ok and tool_bucket_max > 0:
        remaining_max = 35 + 25 + 10 + 10  # 80
        if remaining_max > 0:
            scale = 100 / remaining_max
            yara_score = min(int(yara_score * scale), 35)
            h_pts = min(int(h_pts * scale), 25)
            intel_pts = min(int(intel_pts * scale), 10)
            extra_pts = min(int(extra_pts * scale), 10)

    score = yara_score + h_pts + tool_pts + intel_pts + extra_pts
    score = min(score, 100)

    if score >= 70:
        level = "CRITICAL"
    elif score >= 40:
        level = "SUSPICIOUS"
    elif score > 10:
        level = "LOW_RISK"
    else:
        level = "CLEAN"

    logger.info(f"Composite risk: {score}/100 ({level})")
    return score, level


def _compute_verdict(result: AnalysisResult) -> str:
    """Compute the authoritative threat verdict.

    The composite risk score is the single source of truth. The verdict
    starts from the composite risk level and only escalates upward based
    on high-confidence individual signals (never downgrades).
    """
    critical_rules = {"pegasus", "zero_click", "root_exploit", "reverse_shell",
                       "novispy", "finspy", "hackingteam", "sandrorat", "dendroid",
                       "stalkerware", "disguised_package", "spyware",
                       "credential_theft", "data_exfil"}

    # --- Baseline from composite risk level ---
    composite = getattr(result, "composite_risk_level", "CLEAN")
    if composite == "CRITICAL":
        return ThreatVerdict.CRITICAL
    elif composite == "SUSPICIOUS":
        verdict = ThreatVerdict.SUSPICIOUS
    else:
        verdict = ThreatVerdict.CLEAN

    # --- Escalation: high-confidence YARA rules always override ---
    for rule_info in result.matched_rules:
        if not rule_info.get("authoritative", True):
            continue
        tags = {t.lower() for t in rule_info.get("tags", [])}
        name = rule_info.get("rule", "").lower()
        if tags & critical_rules or any(cr in name for cr in critical_rules):
            return ThreatVerdict.CRITICAL

    # --- Escalation: critical heuristic risk ---
    if result.heuristic_result:
        if result.heuristic_result.get("risk_level") == "CRITICAL":
            return ThreatVerdict.CRITICAL

    # --- Escalation: PCAP C2 hits ---
    if result.pcap_results and result.pcap_results.get("c2_hits"):
        return ThreatVerdict.CRITICAL

    # --- Escalation: MVT critical indicators ---
    for mvt in result.mvt_results:
        if mvt.get("threat_level") in ("critical", "high"):
            return ThreatVerdict.CRITICAL

    # --- Escalation: capa critical capabilities ---
    for capa in result.capa_results:
        mal_caps = capa.get("malicious_capabilities", [])
        if any(c.get("severity") == "critical" for c in mal_caps):
            return ThreatVerdict.CRITICAL

    # --- Escalation: ALEAPP stalkerware ---
    for aleapp in result.aleapp_results:
        for finding in aleapp.get("findings", []):
            if finding.get("severity") == "CRITICAL":
                return ThreatVerdict.CRITICAL
        if aleapp.get("stalkerware_found"):
            return ThreatVerdict.CRITICAL

    # --- Escalation: APKiD critical ---
    for apkid in result.apkid_results:
        if apkid.get("threat_level") == "CRITICAL":
            return ThreatVerdict.CRITICAL

    # --- Escalation: Quark critical ---
    for quark in result.quark_results:
        if quark.get("threat_level") == "CRITICAL":
            return ThreatVerdict.CRITICAL

    # --- Escalation: OTX/intel C2 ---
    for intel in result.intel_results:
        if intel.get("c2_match"):
            return ThreatVerdict.CRITICAL

    # --- Escalation: entropy dual risk ---
    for ent in result.entropy_results:
        if ent.get("exfil_risk") and ent.get("obfuscation_risk"):
            return ThreatVerdict.CRITICAL

    # --- Escalation: correlation critical ---
    corr = result.correlation_result or {}
    if corr.get("critical_count", 0) >= 2:
        return ThreatVerdict.CRITICAL

    # If no escalation triggered, return the composite-derived baseline
    return verdict


def _explain_verdict(result: AnalysisResult) -> list[str]:
    """Explain why the authoritative verdict may exceed the weighted score band."""
    reasons = [
        f"Weighted score band: {result.composite_risk_level} "
        f"({result.composite_risk_score}/100)."
    ]
    if result.verdict == result.composite_risk_level:
        contextual = [
            rule.get("rule", "unknown")
            for rule in result.matched_rules
            if not rule.get("authoritative", True)
        ]
        if contextual:
            reasons.append(
                "Context-only YARA matches did not independently escalate the verdict: "
                + ", ".join(dict.fromkeys(contextual))
                + "."
            )
        return reasons

    critical_rules = {
        "pegasus", "zero_click", "root_exploit", "reverse_shell", "novispy",
        "finspy", "hackingteam", "sandrorat", "dendroid", "stalkerware",
        "disguised_package", "spyware", "credential_theft", "data_exfil",
    }
    escalators = []
    for rule_info in result.matched_rules:
        if not rule_info.get("authoritative", True):
            continue
        tags = {str(tag).lower() for tag in rule_info.get("tags", [])}
        name = str(rule_info.get("rule", ""))
        lowered_name = name.lower()
        if tags & critical_rules or any(token in lowered_name for token in critical_rules):
            escalators.append(name)
    if escalators:
        reasons.append(
            "Final verdict escalated to CRITICAL by high-confidence YARA policy: "
            + ", ".join(dict.fromkeys(escalators))
            + "."
        )
    else:
        contextual = [
            rule.get("rule", "unknown")
            for rule in result.matched_rules
            if not rule.get("authoritative", True)
        ]
        if contextual and result.verdict == result.composite_risk_level:
            reasons.append(
                "Context-only YARA matches did not independently escalate the verdict: "
                + ", ".join(dict.fromkeys(contextual))
                + "."
            )
        else:
            reasons.append(
                f"Final verdict escalated to {result.verdict} by an authoritative "
                "high-confidence signal; inspect tool findings for supporting evidence."
            )
    return reasons


def _build_summary(result: AnalysisResult) -> str:
    if result.verdict == ThreatVerdict.CLEAN:
        fstat = result.filter_stats
        filter_note = ""
        if fstat.get("noise_reduction_pct", 0) > 0:
            filter_note = f"\nLog filter: {fstat['noise_reduction_pct']:.0f}% noise removed."
        contextual_matches = [
            match for match in result.matched_rules
            if not match.get("authoritative", True)
        ]
        yara_note = (
            f"\n{len(contextual_matches)} context-only YARA matches retained for review; "
            "none qualified as direct malware evidence."
            if contextual_matches
            else "\nNo YARA rule matches."
        )
        return (
            f"[CLEAN] DEVICE CLEAN\n\n"
            f"Scanned {result.scanned_files} forensic artifacts.{filter_note}\n"
            f"{yara_note} No malicious IPs detected."
        )

    lines = []
    if result.verdict == ThreatVerdict.CRITICAL:
        lines.append("[CRITICAL] CRITICAL THREAT DETECTED")
    else:
        lines.append("[SUSPICIOUS] SUSPICIOUS ACTIVITY DETECTED")

    lines.append(f"\nScanned {result.scanned_files} forensic artifacts.")

    if result.matched_rules:
        lines.append(f"\n--- YARA Matches ({len(result.matched_rules)}) ---")
        for r in result.matched_rules:
            lines.append(
                f"  Rule: {r['rule']} | File: {r['file']} | Tags: {', '.join(r['tags'])}"
            )

    if result.suspicious_ips:
        lines.append(f"\n--- Malicious IPs ({len(result.suspicious_ips)}) ---")
        for ip in sorted(set(result.suspicious_ips)):
            lines.append(f"  {ip}")

    if result.vt_results:
        lines.append(f"\n--- VirusTotal Results ---")
        for vt in result.vt_results:
            if "malicious_detections" in vt:
                lines.append(
                    f"  {vt['ip']}: {vt['malicious_detections']}/{vt['total_engines']} "
                    f"engines | Country: {vt.get('country', '?')}"
                )
            else:
                lines.append(f"  {vt['ip']}: {vt.get('status', 'unknown')}")

    if result.mvt_results:
        lines.append(f"\n--- MVT Spyware Analysis ({len(result.mvt_results)}) ---")
        for m in result.mvt_results:
            lines.append(
                f"  [{m.get('threat_level', '?').upper()}] {m.get('indicator', '')} "
                f"| Source: {m.get('source_file', '')}"
            )

    if result.aleapp_results:
        lines.append(f"\n--- ALEAPP Artifact Analysis ({len(result.aleapp_results)}) ---")
        for a in result.aleapp_results:
            if a.get("stalkerware_found"):
                lines.append(f"  [CRITICAL] Stalkerware package detected: {a.get('package_name', '')}")
            if a.get("suspicious_packages"):
                lines.append(f"  [WARNING] Suspicious packages: {', '.join(a['suspicious_packages'])}")

    if result.capa_results:
        lines.append(f"\n--- Capa Static Analysis ({len(result.capa_results)}) ---")
        for c in result.capa_results:
            mal_caps = c.get("malicious_capabilities", [])
            for mc in mal_caps:
                lines.append(
                    f"  [{mc.get('severity', '?').upper()}] {mc.get('name', '')} "
                    f"| Target: {c.get('target', '')}"
                )

    if result.apkid_results:
        lines.append(f"\n--- APKiD Packer Detection ({len(result.apkid_results)}) ---")
        for a in result.apkid_results:
            if a.get("packers_found") or a.get("anti_analysis"):
                lines.append(
                    f"  [{a.get('threat_level', '?').upper()}] {a.get('package_name', '')} "
                    f"| Packers: {', '.join(a.get('packers_found', [])) or 'none'} "
                    f"| Anti-analysis: {', '.join(a.get('anti_analysis', [])) or 'none'} "
                    f"| Risk: {a.get('risk_score', 0)}"
                )

    if result.quark_results:
        lines.append(f"\n--- Quark Behavioral Analysis ({len(result.quark_results)}) ---")
        for q in result.quark_results:
            if q.get("threat_level") != "CLEAN":
                lines.append(
                    f"  [{q.get('threat_level', '?').upper()}] {q.get('package_name', '')} "
                    f"| Score: {q.get('threat_score', 0):.2f} "
                    f"| Behaviors: {q.get('capability_count', 0)} "
                    f"| Rules matched: {q.get('rule_match_count', 0)}"
                )
                for b in q.get("malicious_behaviors", [])[:5]:
                    lines.append(f"    -> {b}")

    if result.intel_results:
        lines.append(f"\n--- Threat Intelligence ({len(result.intel_results)} IPs) ---")
        for i in result.intel_results:
            if i.get("is_malicious"):
                pulse_info = ""
                if i.get("otx_pulses"):
                    pulse_info = f" | OTX pulses: {len(i['otx_pulses'])}"
                lines.append(
                    f"  [{i.get('threat_score', 0)}] {i.get('ip', '')} "
                    f"| Source: {i.get('source', '')} "
                    f"| Abuse confidence: {i.get('abuse_confidence', 0)}%"
                    f"{pulse_info}"
                )
                if i.get("c2_match"):
                    lines.append(f"    -> C2 INFRASTRUCTURE MATCH")

    if result.entropy_results:
        lines.append(f"\n--- Entropy Analysis ({len(result.entropy_results)} high-entropy files) ---")
        for e in result.entropy_results:
            risk_tags = []
            if e.get("exfil_risk"):
                risk_tags.append("EXFIL")
            if e.get("obfuscation_risk"):
                risk_tags.append("OBFUSCATION")
            lines.append(
                f"  [{e.get('classification', '?').upper()}] {Path(e.get('file_path', '')).name} "
                f"| H={e.get('overall_entropy', 0):.2f} (max={e.get('max_block_entropy', 0):.2f}) "
                f"| Size: {e.get('file_size', 0)} bytes "
                f"| Flags: {', '.join(risk_tags)}"
            )

    if result.browser_results:
        lines.append(f"\n--- Browser Forensics ({len(result.browser_results)}) ---")
        for b in result.browser_results:
            sus_count = len(b.get("suspicious_visits", []))
            lines.append(
                f"  Package: {b.get('package_name', '')} "
                f"| Visits: {b.get('total_visits', 0)} "
                f"| Logins: {b.get('total_logins', 0)} "
                f"| Suspicious URLs: {sus_count}"
            )
            for sv in b.get("suspicious_visits", [])[:5]:
                lines.append(f"    -> {sv.get('url', '')[:80]}")

    corr = result.correlation_result or {}
    if corr.get("total_correlations", 0) > 0:
        lines.append(f"\n--- Cross-Tool Correlation ({corr['total_correlations']} events) ---")
        lines.append(f"  CRITICAL: {corr.get('critical_count', 0)} | HIGH: {corr.get('high_count', 0)}")
        for ev in corr.get("events", [])[:10]:
            lines.append(
                f"  [{ev.get('severity', '?')}] {ev.get('rule_id', '')}: "
                f"{ev.get('package_name', '')} ({', '.join(ev.get('matched_tools', []))})"
            )

    # Tool health report
    ts = result.tool_status
    if ts:
        ok_tools = [k for k, v in ts.items() if v == "ok"]
        unavailable_tools = [k for k, v in ts.items() if v == "unavailable"]
        failed_tools = [k for k, v in ts.items() if v == "error"]
        skipped_tools = [k for k, v in ts.items() if v.startswith("skipped")]
        disabled_tools = [k for k, v in ts.items() if v == "disabled"]
        if unavailable_tools or failed_tools or skipped_tools:
            lines.append(f"\n--- Tool Health ---")
            lines.append(f"  Ran successfully: {', '.join(ok_tools) if ok_tools else 'none'}")
            if skipped_tools:
                lines.append(f"  Skipped (no supported input): {', '.join(skipped_tools)}")
            if unavailable_tools:
                lines.append(f"  Requested but unavailable: {', '.join(unavailable_tools)}")
            if failed_tools:
                lines.append(f"  Failed during execution: {', '.join(failed_tools)}")
            if disabled_tools:
                lines.append(f"  Disabled by configuration: {', '.join(disabled_tools)}")

    return "\n".join(lines)


def _report(on_progress, percent, message):
    if on_progress:
        try:
            on_progress(percent, message)
        except Exception:
            pass
