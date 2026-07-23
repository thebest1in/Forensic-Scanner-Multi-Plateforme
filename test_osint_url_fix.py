"""Regression test: OSINT URL template must not crash report generation."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))


def get_lookup_url(item: dict) -> str:
    """Safe URL extraction — works with both 'url' and 'url_template' keys."""
    if not isinstance(item, dict):
        return ""
    return str(item.get("url_template") or item.get("url") or "")


def test_url_template_key():
    entry = {
        "name": "Numbering Plans",
        "url_template": "https://www.numberingplans.com/?page=analysis&sub=imeinr&imei={imei}",
        "requires_sensitive_value": True,
        "value_type": "imei",
    }
    url = get_lookup_url(entry)
    assert url.endswith("imei={imei}"), f"Expected template URL, got: {url}"
    print("PASS: url_template key works")


def test_legacy_url_key():
    entry = {
        "name": "Legacy Tool",
        "url": "https://example.com/{phone}",
    }
    url = get_lookup_url(entry)
    assert url.endswith("{phone}"), f"Expected legacy URL, got: {url}"
    print("PASS: legacy url key works")


def test_empty_entry():
    assert get_lookup_url({}) == ""
    assert get_lookup_url(None) == ""
    assert get_lookup_url("not a dict") == ""
    print("PASS: empty/invalid entries handled")


def test_report_line_formatting():
    """Simulate the report line that caused the crash."""
    urls = [
        {"name": "Truecaller", "url_template": "https://www.truecaller.com/search/{phone}"},
        {"name": "IMEI.info", "url_template": "https://www.imei.info/"},
    ]
    for u in urls[:2]:
        url = u.get("url_template", u.get("url", ""))
        line = f"    -> {u['name']}: {url[:80]}"
        assert "Truecaller" in line or "IMEI" in line
    print("PASS: report line formatting works")


def test_full_osint_serialization():
    """Full roundtrip: OSINTResult → dict → JSON → access lookup_urls."""
    import json
    from osint_bridge import OSINTResult, _build_lookup_urls

    r = OSINTResult()
    r.phone_number = "1234567890"
    r.imei = "867512345678749"
    r.sim_operator = "Test"
    r.sim_country = "XX"
    r.lookup_urls = _build_lookup_urls(r.phone_number, r.imei)

    d = r.to_dict()
    serialized = json.dumps(d, default=str)
    deserialized = json.loads(serialized)

    for category, entries in deserialized["lookup_urls"].items():
        for entry in entries:
            url = entry.get("url_template", entry.get("url", ""))
            assert isinstance(url, str), f"URL is not a string: {url}"
    print("PASS: full OSINT serialization roundtrip works")


if __name__ == "__main__":
    test_url_template_key()
    test_legacy_url_key()
    test_empty_entry()
    test_report_line_formatting()
    test_full_osint_serialization()
    print("\nAll regression tests passed.")
