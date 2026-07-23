"""Unit tests for iOS forensic parsers.

Tests backup parsing, device info, and parser logic without requiring
a real iOS backup or device connection.
"""
import json
import plistlib
import sqlite3
import tempfile
from pathlib import Path

from ios.backup import (
    read_manifest_database,
    read_plist,
    resolve_backup_file,
    get_backup_domains,
    parse_info_plist,
    parse_status_plist,
    extract_backup_tree,
)


def _create_mock_manifest_db(backup_dir: Path) -> Path:
    """Create a mock Manifest.db with sample records."""
    db_path = backup_dir / "Manifest.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute("CREATE TABLE IF NOT EXISTS Files (fileID TEXT, domain TEXT, relativePath TEXT, flags INTEGER, file BLOB)")
    conn.execute("INSERT INTO Files VALUES ('aabb11223344556677889900aabbccdd', 'HomeDomain', 'Library/SMS/sms.db', 1, NULL)")
    conn.execute("INSERT INTO Files VALUES ('bbcc22334455667788990011bbccddee', 'AppDomain-com.example.app', 'Documents/data.json', 1, NULL)")
    conn.execute("INSERT INTO Files VALUES ('ccdd33445566778899001122ccddee00', 'HomeDomain', 'Library/Safari/History.db', 1, NULL)")
    conn.execute("INSERT INTO Files VALUES ('ddee44556677889900112233ddeeff00', 'RootDomain', 'System/Library/Keychains/chain.db', 1, NULL)")
    conn.commit()
    conn.close()
    return db_path


def _create_mock_plist(backup_dir: Path, name: str, data: dict) -> Path:
    """Create a mock plist file."""
    path = backup_dir / name
    with path.open("wb") as f:
        plistlib.dump(data, f)
    return path


def _create_backup_files(backup_dir: Path) -> None:
    """Create a minimal mock iOS backup structure."""
    # Create hashed directories and files
    file_ids = [
        "aabb11223344556677889900aabbccdd",
        "bbcc22334455667788990011bbccddee",
        "ccdd33445566778899001122ccddee00",
        "ddee44556677889900112233ddeeff00",
    ]
    for fid in file_ids:
        dir_path = backup_dir / fid[:2]
        dir_path.mkdir(exist_ok=True)
        file_path = dir_path / fid
        file_path.write_text(f"mock content for {fid}", encoding="utf-8")

    # Info.plist
    _create_mock_plist(backup_dir, "Info.plist", {
        "DeviceName": "Test iPhone",
        "ProductType": "iPhone15,3",
        "ProductVersion": "18.0",
        "BuildVersion": "22A3354",
        "SerialNumber": "ABC123DEF456",
        "UniqueDeviceID": "00008101-001A2B3C4D5E6F7G",
        "LastBackupDate": "2026-07-23T12:00:00Z",
        "IsEncrypted": False,
    })

    # Status.plist
    _create_mock_plist(backup_dir, "Status.plist", {
        "BackupState": "new",
        "IsFullBackup": True,
        "Date": "2026-07-23T12:00:00Z",
    })


def test_read_plist():
    """Test plist reading."""
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "test.plist"
        data = {"key": "value", "nested": {"a": 1}}
        with path.open("wb") as f:
            plistlib.dump(data, f)

        result = read_plist(path)
        assert result["key"] == "value"
        assert result["nested"]["a"] == 1
    print("PASS: read_plist")


def test_read_plist_missing():
    """Test reading a missing plist returns empty dict."""
    result = read_plist(Path("/nonexistent/file.plist"))
    assert result == {}
    print("PASS: read_plist_missing")


def test_manifest_database():
    """Test Manifest.db parsing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        backup_dir = Path(tmpdir)
        _create_mock_manifest_db(backup_dir)

        records = read_manifest_database(backup_dir)
        assert len(records) == 4
        domains = {r["domain"] for r in records}
        assert "HomeDomain" in domains
        assert "AppDomain-com.example.app" in domains

        # Check specific records
        sms_record = [r for r in records if "sms.db" in r["relative_path"]]
        assert len(sms_record) == 1
        assert sms_record[0]["file_id"] == "aabb11223344556677889900aabbccdd"
    print("PASS: manifest_database")


def test_resolve_backup_file():
    """Test backup file resolution."""
    with tempfile.TemporaryDirectory() as tmpdir:
        backup_dir = Path(tmpdir)
        file_id = "aabb11223344556677889900aabbccdd"
        expected = backup_dir / "aa" / file_id

        result = resolve_backup_file(backup_dir, file_id)
        assert result == expected
    print("PASS: resolve_backup_file")


def test_get_backup_domains():
    """Test domain grouping."""
    records = [
        {"domain": "HomeDomain", "relative_path": "a.txt", "file_id": "111", "flags": 1, "metadata": None},
        {"domain": "HomeDomain", "relative_path": "b.txt", "file_id": "222", "flags": 1, "metadata": None},
        {"domain": "AppDomain-com.test", "relative_path": "c.txt", "file_id": "333", "flags": 1, "metadata": None},
    ]
    domains = get_backup_domains(records)
    assert len(domains) == 2
    assert len(domains["HomeDomain"]) == 2
    assert len(domains["AppDomain-com.test"]) == 1
    print("PASS: get_backup_domains")


def test_info_plist():
    """Test Info.plist parsing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        backup_dir = Path(tmpdir)
        _create_mock_plist(backup_dir, "Info.plist", {
            "DeviceName": "Test iPhone",
            "ProductType": "iPhone15,3",
            "ProductVersion": "18.0",
            "SerialNumber": "ABC123",
        })

        result = parse_info_plist(backup_dir)
        assert result["DeviceName"] == "Test iPhone"
        assert result["ProductType"] == "iPhone15,3"
    print("PASS: info_plist")


def test_status_plist():
    """Test Status.plist parsing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        backup_dir = Path(tmpdir)
        _create_mock_plist(backup_dir, "Status.plist", {
            "BackupState": "new",
            "IsFullBackup": True,
        })

        result = parse_status_plist(backup_dir)
        assert result["BackupState"] == "new"
        assert result["IsFullBackup"] is True
    print("PASS: status_plist")


def test_backup_tree():
    """Test backup tree extraction."""
    with tempfile.TemporaryDirectory() as tmpdir:
        backup_dir = Path(tmpdir)
        _create_mock_manifest_db(backup_dir)
        _create_backup_files(backup_dir)

        tree = extract_backup_tree(backup_dir)
        assert "HomeDomain" in tree
        assert tree["HomeDomain"]["file_count"] == 2
        assert "AppDomain-com.example.app" in tree
    print("PASS: backup_tree")


def test_empty_manifest():
    """Test handling of missing Manifest.db."""
    with tempfile.TemporaryDirectory() as tmpdir:
        backup_dir = Path(tmpdir)  # no Manifest.db created
        records = read_manifest_database(backup_dir)
        assert records == []
    print("PASS: empty_manifest")


def test_full_backup_workflow():
    """Test a complete backup parsing workflow."""
    with tempfile.TemporaryDirectory() as tmpdir:
        backup_dir = Path(tmpdir)
        _create_mock_manifest_db(backup_dir)
        _create_backup_files(backup_dir)

        # Read all records
        records = read_manifest_database(backup_dir)
        assert len(records) == 4

        # Group by domain
        domains = get_backup_domains(records)
        assert "HomeDomain" in domains

        # Resolve a file path
        file_id = "aabb11223344556677889900aabbccdd"
        file_path = resolve_backup_file(backup_dir, file_id)
        assert file_path.exists()

        # Parse Info.plist
        info = parse_info_plist(backup_dir)
        assert info["DeviceName"] == "Test iPhone"

        # Build tree
        tree = extract_backup_tree(backup_dir)
        total_files = sum(d["file_count"] for d in tree.values())
        assert total_files == 4
    print("PASS: full_backup_workflow")


def test_device_info_summary():
    """Test device info extraction from backup."""
    with tempfile.TemporaryDirectory() as tmpdir:
        backup_dir = Path(tmpdir)
        _create_mock_plist(backup_dir, "Info.plist", {
            "DeviceName": "Test iPhone",
            "ProductType": "iPhone15,3",
            "ProductVersion": "18.0",
            "BuildVersion": "22A3354",
            "SerialNumber": "ABC123DEF456",
            "UniqueDeviceID": "UDID123",
            "LastBackupDate": "2026-07-23T12:00:00Z",
            "IsEncrypted": False,
        })

        from ios.device_info import extract_device_summary
        summary = extract_device_summary(backup_dir)
        assert summary["product_type"] == "iPhone15,3"
        assert summary["product_version"] == "18.0"
        assert summary["device_name"] == "Test iPhone"
        # Serial should be redacted
        assert summary["serial_number_redacted"].startswith("*")
    print("PASS: device_info_summary")


def test_applications_parsing():
    """Test installed applications parsing from backup."""
    with tempfile.TemporaryDirectory() as tmpdir:
        backup_dir = Path(tmpdir)
        _create_mock_manifest_db(backup_dir)
        # Add more app domain records
        db_path = backup_dir / "Manifest.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute("INSERT INTO Files VALUES ('eeff55667788990011223344eeff0011', 'AppDomain-com.spy.tracker', 'Documents/logs.db', 1, NULL)")
        conn.execute("INSERT INTO Files VALUES ('ff0066778899001122334455ff001122', 'AppDomain-com.normal.app', 'Documents/data.txt', 1, NULL)")
        conn.commit()
        conn.close()

        from ios.applications import parse_installed_apps
        result = parse_installed_apps(backup_dir)
        assert result["total"] >= 2
        assert "com.spy.tracker" in [a["bundle_id"] for a in result["apps"]]
        # Check suspicious detection
        spy_app = [a for a in result["apps"] if a["bundle_id"] == "com.spy.tracker"]
        assert len(spy_app) == 1
        assert spy_app[0]["suspicious"] is True
    print("PASS: applications_parsing")


if __name__ == "__main__":
    test_read_plist()
    test_read_plist_missing()
    test_manifest_database()
    test_resolve_backup_file()
    test_get_backup_domains()
    test_info_plist()
    test_status_plist()
    test_backup_tree()
    test_empty_manifest()
    test_full_backup_workflow()
    test_device_info_summary()
    test_applications_parsing()
    print("\nAll iOS parser tests passed!")
