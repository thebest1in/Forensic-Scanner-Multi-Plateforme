import hashlib
from pathlib import Path


class HashAnalyzer:
    """File hash computation and known-bad hash matching."""

    KNOWN_MALICIOUS_HASHES = set()

    def __init__(self, hash_db_path: str = ""):
        self.hash_db_path = Path(hash_db_path) if hash_db_path else Path(__file__).parent.parent / "rules" / "iocs" / "hashes.txt"
        self._load_hash_db()

    def _load_hash_db(self):
        if self.hash_db_path.exists():
            for line in self.hash_db_path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    self.KNOWN_MALICIOUS_HASHES.add(line.lower())

    def compute_hashes(self, filepath: Path) -> dict:
        hashes = {"md5": "", "sha1": "", "sha256": ""}
        try:
            with open(filepath, "rb") as f:
                md5 = hashlib.md5()
                sha1 = hashlib.sha1()
                sha256 = hashlib.sha256()
                while chunk := f.read(8192):
                    md5.update(chunk)
                    sha1.update(chunk)
                    sha256.update(chunk)
                hashes["md5"] = md5.hexdigest()
                hashes["sha1"] = sha1.hexdigest()
                hashes["sha256"] = sha256.hexdigest()
        except Exception:
            pass
        return hashes

    def check_against_db(self, hashes: dict) -> dict:
        result = {"known_malicious": False, "matches": []}
        for algo, h in hashes.items():
            if h and h.lower() in self.KNOWN_MALICIOUS_HASHES:
                result["known_malicious"] = True
                result["matches"].append({"algorithm": algo, "hash": h})
        return result

    def scan_file(self, filepath: Path) -> dict:
        hashes = self.compute_hashes(filepath)
        db_check = self.check_against_db(hashes)
        return {
            "file": str(filepath.name),
            "hashes": hashes,
            "known_malicious": db_check["known_malicious"],
            "matches": db_check["matches"],
        }

    def scan_directory(self, directory: Path) -> list[dict]:
        results = []
        for f in directory.rglob("*"):
            if f.is_file():
                result = self.scan_file(f)
                if result["known_malicious"]:
                    results.append(result)
        return results
