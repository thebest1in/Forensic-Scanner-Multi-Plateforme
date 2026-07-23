"""Install timeline analysis — package install history and first-seen tracking."""


def check_install_timeline(content: str, source_file: str) -> list[dict]:
    """Parse install history output for recent and suspicious installs."""
    findings = []
    packages = []

    for line in content.splitlines():
        line = line.strip()
        if not line or "package:" not in line.lower():
            continue
        pkg = {
            "raw": line,
            "name": "",
            "path": "",
            "install_time": "",
        }
        if "=" in line:
            left, _, right = line.partition("=")
            pkg["name"] = right.strip()
            if "package:" in left.lower():
                pkg["path"] = left.split(":", 1)[-1].strip()
        if "installTime=" in line:
            start = line.index("installTime=") + 12
            end = line.find(" ", start)
            pkg["install_time"] = line[start:end] if end > start else line[start:]
        if "lastUpdateTime=" in line:
            start = line.index("lastUpdateTime=") + 15
            end = line.find(" ", start)
            pkg["last_update"] = line[start:end] if end > start else line[start:]

        if pkg["name"]:
            packages.append(pkg)

    suspicious_install_paths = ("/data/local/tmp/", "/sdcard/Download/", "/mnt/")

    for pkg in packages:
        path = pkg.get("path", "")
        for sus_path in suspicious_install_paths:
            if sus_path in path:
                findings.append({
                    "type": "SUSPICIOUS_INSTALL_PATH",
                    "severity": "HIGH",
                    "package": pkg["name"],
                    "path": path,
                    "evidence": f"Package installed from suspicious path: {path}",
                    "file": source_file,
                })
                break

    if packages:
        findings.append({
            "type": "INSTALL_SUMMARY",
            "severity": "INFO",
            "total_packages": len(packages),
            "evidence": f"Found {len(packages)} third-party package install records",
            "file": source_file,
        })

    return findings
