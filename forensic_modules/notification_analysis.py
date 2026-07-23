"""Notification history analysis — social engineering detection."""

SUSPICIOUS_KEYWORDS = {
    "virus", "malware", "infected", "hack", "stolen", "compromised",
    "verify your account", "suspended", "locked", "unauthorized",
    "login attempt", "security alert", "action required", "click here",
    "bank", "paypal", "credit card", "ssn", "password", "reset",
}

PHISHING_PATTERNS = {
    "amazon", "apple", "google", "microsoft", "netflix", "facebook",
    "instagram", "whatsapp", "telegram", "dhl", "ups", "fedex",
}


def check_notifications(content: str, source_file: str) -> list[dict]:
    """Parse dumpsys notification output for social engineering indicators."""
    findings = []
    notifications = []
    current = {}

    for line in content.splitlines():
        line = line.strip()
        if "NotificationRecord:" in line or "pkg=" in line:
            if current:
                notifications.append(current)
            current = {"raw": line, "package": "", "title": "", "text": "", "priority": ""}
            if "pkg=" in line:
                start = line.index("pkg=") + 4
                end = line.find(" ", start)
                current["package"] = line[start:end] if end > start else line[start:]
            if "title=" in line:
                start = line.index("title=") + 6
                end = line.find("'", start)
                if end > start:
                    current["title"] = line[start:end]
            if "priority=" in line:
                start = line.index("priority=") + 9
                end = line.find(" ", start)
                current["priority"] = line[start:end] if end > start else line[start:]

        elif current:
            if "title" not in current or not current["title"]:
                current["title"] = line
            current["text"] = line

    if current:
        notifications.append(current)

    for notif in notifications:
        combined = f"{notif.get('title', '')} {notif.get('text', '')}".lower()
        pkg = notif.get("package", "")

        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in combined:
                findings.append({
                    "type": "SUSPICIOUS_NOTIFICATION",
                    "severity": "MEDIUM",
                    "package": pkg,
                    "title": notif.get("title", ""),
                    "keyword": keyword,
                    "evidence": f"Suspicious notification keyword '{keyword}' from {pkg}",
                    "file": source_file,
                })
                break

        for brand in PHISHING_PATTERNS:
            if brand in combined and pkg and brand not in pkg.lower():
                findings.append({
                    "type": "PHISHING_NOTIFICATION",
                    "severity": "HIGH",
                    "package": pkg,
                    "title": notif.get("title", ""),
                    "impersonation": brand,
                    "evidence": f"Possible {brand} impersonation from package {pkg}",
                    "file": source_file,
                })
                break

    return findings
