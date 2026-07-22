"""Account analysis — enumerate synced accounts, detect unauthorized sync."""

KNOWN_ACCOUNT_TYPES = {
    "com.google": "Google",
    "com.microsoft.launcher": "Microsoft",
    "com.whatsapp": "WhatsApp",
    "org.telegram.messenger": "Telegram",
    "com.facebook.auth": "Facebook",
    "com.twitter.android.auth": "Twitter/X",
    "com.apple.id": "Apple ID",
    "com.huawei.cloud": "Huawei Cloud",
    "com.xiaomi.xmsf": "Xiaomi Mi Account",
}


def check_accounts(content: str, source_file: str) -> list[dict]:
    """Parse dumpsys account output and enumerate synced accounts."""
    findings = []
    accounts = []
    account_types = set()

    for line in content.splitlines():
        line = line.strip()
        if "Account {" in line or "account {" in line:
            accounts.append(line)
        if "type=" in line:
            atype = line.split("type=")[-1].split()[0].strip().rstrip("}")
            if atype:
                account_types.add(atype)

    if accounts:
        findings.append({
            "type": "ACCOUNT_INVENTORY",
            "severity": "INFO",
            "account_count": len(accounts),
            "account_types": sorted(account_types),
            "evidence": f"Found {len(accounts)} synced accounts",
            "file": source_file,
        })

    cloud_accounts = [a for a in account_types if "cloud" in a.lower() or "sync" in a.lower()]
    if cloud_accounts:
        findings.append({
            "type": "CLOUD_SYNC",
            "severity": "INFO",
            "cloud_types": cloud_accounts,
            "evidence": f"Cloud sync accounts detected: {', '.join(cloud_accounts)}",
            "file": source_file,
        })

    return findings
