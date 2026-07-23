import re
import subprocess
from dataclasses import dataclass, field

from core import ADB_BINARY

OSINT_RESOURCES = {
    "phone_lookup": [
        {"name": "Truecaller", "url": "https://www.truecaller.com/search/{phone}"},
        {"name": "Sync.me", "url": "https://sync.me/search/?number={phone}"},
        {"name": "Spokeo", "url": "https://www.spokeo.com/phone-lookup/{phone}"},
    ],
    "imei_lookup": [
        {"name": "IMEI.info", "url": "https://www.imei.info/"},
        {"name": "Numbering Plans", "url": "https://www.numberingplans.com/?page=analysis&sub=imeinr&imei={imei}"},
    ],
    "device_tracking": [
        {"name": "Google Find My Device", "url": "https://www.google.com/android/find"},
        {"name": "Xiaomi Find Device", "url": "https://i.mi.com/"},
    ],
}

MCC_MNC_MAP = {
    "604/01": {"country": "Morocco", "operator": "Maroc Telecom"},
    "604/02": {"country": "Morocco", "operator": "Orange Morocco"},
    "604/03": {"country": "Morocco", "operator": "inwi"},
    "310/260": {"country": "USA", "operator": "T-Mobile"},
    "310/410": {"country": "USA", "operator": "AT&T"},
    "311/480": {"country": "USA", "operator": "Verizon"},
    "234/10": {"country": "UK", "operator": "BT"},
    "234/15": {"country": "UK", "operator": "Vodafone UK"},
    "262/01": {"country": "Germany", "operator": "T-Mobile DE"},
    "262/02": {"country": "Germany", "operator": "Vodafone DE"},
}


@dataclass
class OSINTResult:
    available: bool = False
    phone_number: str = ""
    imei: str = ""
    sim_operator: str = ""
    sim_country: str = ""
    mcc_mnc: str = ""
    lookup_urls: dict = field(default_factory=dict)
    device_registered: dict = field(default_factory=dict)
    details: str = ""

    @property
    def severity(self) -> str:
        if not self.available:
            return "UNAVAILABLE"
        return "INFO"

    def to_dict(self) -> dict:
        imei_display = self.imei
        if len(self.imei) >= 11:
            imei_display = f"{self.imei[:4]}{'*' * (len(self.imei) - 7)}{self.imei[-3:]}"
        return {
            "available": self.available,
            "phone_number": "",
            "imei": imei_display,
            "sim_operator": self.sim_operator,
            "sim_country": self.sim_country,
            "mcc_mnc": self.mcc_mnc,
            "lookup_urls": self.lookup_urls,
            "device_registered": self.device_registered,
            "severity": self.severity,
            "details": self.details,
        }


def _get_phone_number() -> str:
    try:
        result = subprocess.run(
            [ADB_BINARY, "shell", "service", "call", "iphonesubinfo", "1"],
            capture_output=True, text=True, timeout=10,
        )
        match = re.search(r"'(.*?)'", result.stdout)
        if match:
            raw = match.group(1)
            digits = re.sub(r"[^0-9]", "", raw)
            if len(digits) >= 10:
                return digits
    except Exception:
        pass
    return ""


def _get_imei() -> str:
    # Method 1: dumpsys iphonesubinfo
    try:
        result = subprocess.run(
            [ADB_BINARY, "shell", "dumpsys", "iphonesubinfo"],
            capture_output=True, text=True, timeout=10,
        )
        match = re.search(r"Device ID\s*[:=]\s*(\d+)", result.stdout)
        if match:
            imei = match.group(1)
            if len(imei) >= 15:
                return imei[:15]
    except Exception:
        pass

    # Method 2: service call with different method numbers
    for method in [1, 3]:
        try:
            result = subprocess.run(
                [ADB_BINARY, "shell", "service", "call", "iphonesubinfo", str(method)],
                capture_output=True, text=True, timeout=10,
            )
            parts = re.findall(r"'(.*?)'", result.stdout)
            if parts:
                raw = "".join(parts)
                digits = re.sub(r"[^0-9]", "", raw)
                if len(digits) >= 15 and not digits.startswith("0000"):
                    return digits[:15]
        except Exception:
            continue

    # Method 3: getprop
    for prop in ["ro.ril.oem.imei", "persist.radio.imei"]:
        try:
            result = subprocess.run(
                [ADB_BINARY, "shell", "getprop", prop],
                capture_output=True, text=True, timeout=5,
            )
            imei = result.stdout.strip()
            if imei and len(imei) >= 15 and imei.isdigit():
                return imei[:15]
        except Exception:
            continue

    return ""


def _get_sim_info() -> tuple[str, str, str]:
    mcc_mnc = ""
    operator = ""
    country = ""
    try:
        result = subprocess.run(
            [ADB_BINARY, "shell", "getprop", "gsm.sim.operator.numeric"],
            capture_output=True, text=True, timeout=5,
        )
        raw = result.stdout.strip()
        mcc_mnc = raw.split(",")[0].strip() if raw else ""
    except Exception:
        pass
    try:
        result = subprocess.run(
            [ADB_BINARY, "shell", "getprop", "gsm.sim.operator.alpha"],
            capture_output=True, text=True, timeout=5,
        )
        raw = result.stdout.strip()
        operator = raw.split(",")[0].strip() if raw else ""
    except Exception:
        pass
    if mcc_mnc and mcc_mnc in MCC_MNC_MAP:
        info = MCC_MNC_MAP[mcc_mnc]
        country = info["country"]
        if not operator:
            operator = info["operator"]
    elif mcc_mnc:
        parts = mcc_mnc.split("/")
        if len(parts) == 2:
            result = subprocess.run(
                [ADB_BINARY, "shell", "getprop", "gsm.sim.operator.iso-country"],
                capture_output=True, text=True, timeout=5,
            )
            country = result.stdout.strip()
    return operator, country, mcc_mnc


def _build_lookup_urls(phone: str, imei: str) -> dict:
    urls = {}
    for category, resources in OSINT_RESOURCES.items():
        urls[category] = []
        for res in resources:
            url_template = res["url"]
            # Never embed real IMEI or phone in report URLs — use templates
            if "{phone}" in url_template:
                url = url_template  # keep template, don't substitute
            elif "{imei}" in url_template:
                url = url_template  # keep template, don't substitute
            else:
                url = url_template
            entry = {"name": res["name"], "url_template": url}
            if "{imei}" in url_template and imei:
                entry["requires_sensitive_value"] = True
                entry["value_type"] = "imei"
            if "{phone}" in url_template and phone:
                entry["requires_sensitive_value"] = True
                entry["value_type"] = "phone"
            urls[category].append(entry)
    return urls


def lookup_device(
    on_progress=None,
) -> OSINTResult:
    """Run OSINT lookups on connected device.

    Extracts phone number, IMEI, SIM info and generates
    lookup URLs for OSINT tools.

    Args:
        on_progress: Progress callback(percent, message)

    Returns:
        OSINTResult with lookup data
    """
    result = OSINTResult()

    if on_progress:
        on_progress(10, "Extracting phone number...")

    result.phone_number = _get_phone_number()

    if on_progress:
        on_progress(30, "Extracting IMEI...")

    result.imei = _get_imei()

    if on_progress:
        on_progress(50, "Getting SIM information...")

    result.sim_operator, result.sim_country, result.mcc_mnc = _get_sim_info()

    if on_progress:
        on_progress(70, "Building OSINT lookup URLs...")

    result.lookup_urls = _build_lookup_urls(result.phone_number, result.imei)

    result.device_registered = {
        "Google": "https://www.google.com/android/find",
        "Xiaomi": "https://i.mi.com/",
    }

    result.available = True
    if len(result.imei) >= 7:
        imei_masked = f"{result.imei[:4]}{'*' * (len(result.imei) - 7)}{result.imei[-3:]}"
    else:
        imei_masked = "N/A"
    result.details = (
        f"OSINT data extracted: IMEI={imei_masked}, "
        f"SIM={result.sim_operator} ({result.sim_country})"
    )

    if on_progress:
        on_progress(100, result.details)

    return result
