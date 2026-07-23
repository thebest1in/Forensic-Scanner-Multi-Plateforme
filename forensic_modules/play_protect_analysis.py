"""Play Protect analysis — verification status and bypass detection."""


def check_play_protect(content: str, source_file: str) -> list[dict]:
    """Parse Play Protect verification status."""
    findings = []
    settings = {}

    for line in content.splitlines():
        line = line.strip()
        if "=" in line:
            key, _, val = line.partition("=")
            key = key.strip()
            val = val.strip()
            if key and val:
                settings[key] = val

    adb_verify = settings.get("verifier_verify_adb_installs", "")
    if adb_verify == "0":
        findings.append({
            "type": "PLAY_PROTECT_DISABLED",
            "severity": "HIGH",
            "setting": "verifier_verify_adb_installs",
            "evidence": "ADB install verification is disabled — APKs installed via ADB bypass Play Protect",
            "file": source_file,
        })

    user_optin = settings.get("package_verifier_user_opt_in", "")
    if user_optin == "0":
        findings.append({
            "type": "PLAY_PROTECT_DISABLED",
            "severity": "HIGH",
            "setting": "package_verifier_user_opt_in",
            "evidence": "User has opted out of package verification (Play Protect disabled)",
            "file": source_file,
        })

    failed_verify = []
    for line in content.splitlines():
        if "verification failure" in line.lower() or "not verified" in line.lower():
            failed_verify.append(line.strip())

    for fail in failed_verify:
        pkg = fail.split()[0] if fail.split() else "unknown"
        findings.append({
            "type": "VERIFICATION_FAILURE",
            "severity": "CRITICAL",
            "package": pkg,
            "evidence": f"Package failed verification: {fail}",
            "file": source_file,
        })

    if not settings and not failed_verify:
        findings.append({
            "type": "PLAY_PROTECT_INFO",
            "severity": "INFO",
            "evidence": "Play Protect status data present but unparseable",
            "file": source_file,
        })

    return findings
