import shutil
from pathlib import Path
from datetime import datetime


class ArtifactCollector:
    """Generic artifact collection from filesystem."""

    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def collect_file(self, source: Path, category: str = "general") -> dict:
        cat_dir = self.output_dir / category
        cat_dir.mkdir(exist_ok=True)
        dest = cat_dir / source.name
        try:
            shutil.copy2(source, dest)
            return {"source": str(source), "dest": str(dest), "status": "copied", "size": dest.stat().st_size}
        except Exception as e:
            return {"source": str(source), "dest": str(dest), "status": "error", "error": str(e)}

    def collect_directory(self, source: Path, category: str = "general", max_size_mb: int = 100) -> list[dict]:
        results = []
        if not source.exists():
            return results
        for f in source.rglob("*"):
            if f.is_file():
                size_mb = f.stat().st_size / (1024 * 1024)
                if size_mb <= max_size_mb:
                    result = self.collect_file(f, category)
                    results.append(result)
        return results

    def collect_by_pattern(self, root: Path, pattern: str, category: str = "pattern") -> list[dict]:
        results = []
        for match in root.glob(pattern):
            if match.is_file():
                result = self.collect_file(match, category)
                results.append(result)
        return results

    def collect_text_content(self, source: Path, category: str = "text") -> dict:
        cat_dir = self.output_dir / category
        cat_dir.mkdir(exist_ok=True)
        dest = cat_dir / source.name
        try:
            content = source.read_text(encoding="utf-8", errors="replace")
            dest.write_text(content, encoding="utf-8")
            return {"source": str(source), "dest": str(dest), "status": "collected", "size": len(content)}
        except Exception as e:
            return {"source": str(source), "dest": str(dest), "status": "error", "error": str(e)}

    def create_manifest(self) -> Path:
        manifest_path = self.output_dir / "MANIFEST.txt"
        lines = [
            f"Artifact Collection Manifest",
            f"Generated: {datetime.now().isoformat()}",
            f"Output Directory: {self.output_dir}",
            f"",
            f"Files collected:",
        ]
        for f in sorted(self.output_dir.rglob("*")):
            if f.is_file() and f.name != "MANIFEST.txt":
                rel = f.relative_to(self.output_dir)
                lines.append(f"  {rel} ({f.stat().st_size} bytes)")
        manifest_path.write_text("\n".join(lines), encoding="utf-8")
        return manifest_path
