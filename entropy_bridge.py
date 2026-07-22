import math
import re
from pathlib import Path
from dataclasses import dataclass, field

from core import logger


# ============================================================
# SHANNON ENTROPY ANALYSIS
# ============================================================

# Thresholds
HIGH_ENTROPY_THRESHOLD = 7.5    # H > 7.5 → likely encrypted/compressed (exfil or obfuscation)
MEDIUM_ENTROPY_THRESHOLD = 6.0  # H > 6.0 → suspicious (encoded payloads)
LOW_ENTROPY_THRESHOLD = 3.0     # H < 3.0 → very low (could be structured data or padding)

# Block size for sliding window entropy analysis
DEFAULT_BLOCK_SIZE = 256
DEFAULT_OVERLAP = 128


@dataclass
class EntropyBlock:
    """A single entropy measurement over a data block."""
    offset: int = 0
    length: int = 0
    entropy: float = 0.0
    classification: str = "normal"  # "normal", "suspicious", "high", "critical"

    def to_dict(self) -> dict:
        return {
            "offset": self.offset,
            "length": self.length,
            "entropy": round(self.entropy, 4),
            "classification": self.classification,
        }


@dataclass
class EntropyResult:
    """Entropy analysis result for a single file or payload."""
    file_path: str = ""
    file_size: int = 0
    overall_entropy: float = 0.0
    max_block_entropy: float = 0.0
    high_entropy_blocks: list[dict] = field(default_factory=list)
    classification: str = "normal"
    exfil_risk: bool = False
    obfuscation_risk: bool = False
    details: str = ""

    def to_dict(self) -> dict:
        return {
            "file_path": self.file_path,
            "file_size": self.file_size,
            "overall_entropy": round(self.overall_entropy, 4),
            "max_block_entropy": round(self.max_block_entropy, 4),
            "high_entropy_block_count": len(self.high_entropy_blocks),
            "high_entropy_blocks": self.high_entropy_blocks[:10],
            "classification": self.classification,
            "exfil_risk": self.exfil_risk,
            "obfuscation_risk": self.obfuscation_risk,
            "details": self.details,
        }


class EntropyBridge:
    """Shannon entropy analysis for detecting encrypted exfil, obfuscated C2,
    and packed payloads in forensic artifacts.

    Shannon entropy H measures the randomness of byte distributions:
    - H = 8.0 → perfectly random (encrypted data, strong crypto)
    - H > 7.5 → high entropy (AES-encrypted exfil, compressed archives)
    - H = 4.0-6.0 → normal text/code
    - H < 3.0 → very low (structured data, repeated patterns)

    Useful for:
    - Detecting encrypted data exfiltration in PCAP captures
    - Flagging obfuscated C2 payloads hiding in normal traffic
    - Identifying packed/encrypted binaries that evade YARA
    - Finding hidden data channels in network logs
    """

    @staticmethod
    def compute_entropy(data: bytes) -> float:
        """Compute Shannon entropy of raw bytes. Returns 0.0-8.0."""
        if not data:
            return 0.0

        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1

        length = len(data)
        entropy = 0.0
        for count in byte_counts:
            if count > 0:
                probability = count / length
                entropy -= probability * math.log2(probability)
        return entropy

    @staticmethod
    def classify_entropy(h: float) -> str:
        """Classify entropy level into threat categories."""
        if h >= HIGH_ENTROPY_THRESHOLD:
            return "critical"
        if h >= MEDIUM_ENTROPY_THRESHOLD:
            return "suspicious"
        return "normal"

    def analyze_file(self, file_path: Path, block_size: int = DEFAULT_BLOCK_SIZE) -> EntropyResult:
        """Analyze a single file's entropy with sliding window blocks."""
        result = EntropyResult(file_path=str(file_path))

        if not file_path.exists():
            return result

        try:
            data = file_path.read_bytes()
        except Exception as e:
            result.details = f"Cannot read file: {e}"
            return result

        result.file_size = len(data)
        if len(data) < 16:
            return result

        result.overall_entropy = self.compute_entropy(data)

        # Sliding window analysis
        high_blocks = []
        max_h = 0.0
        overlap = min(DEFAULT_OVERLAP, block_size // 2)

        for offset in range(0, len(data) - block_size + 1, block_size - overlap):
            block = data[offset:offset + block_size]
            h = self.compute_entropy(block)
            max_h = max(max_h, h)

            if h >= MEDIUM_ENTROPY_THRESHOLD:
                classification = self.classify_entropy(h)
                high_blocks.append(EntropyBlock(
                    offset=offset, length=len(block),
                    entropy=h, classification=classification,
                ).to_dict())

        result.max_block_entropy = max_h
        result.high_entropy_blocks = high_blocks

        # Classify overall
        result.classification = self.classify_entropy(result.overall_entropy)

        # Risk assessment
        result.exfil_risk = (
            result.overall_entropy >= HIGH_ENTROPY_THRESHOLD
            or len([b for b in high_blocks if b["classification"] == "critical"]) >= 3
        )
        result.obfuscation_risk = (
            result.max_block_entropy >= HIGH_ENTROPY_THRESHOLD
            and len(high_blocks) >= 2
        )

        if result.exfil_risk or result.obfuscation_risk:
            logger.warning(
                f"Entropy: {file_path.name} -> H={result.overall_entropy:.2f} "
                f"(max={result.max_block_entropy:.2f}) "
                f"exfil={result.exfil_risk} obfuscation={result.obfuscation_risk}"
            )
        return result

    def analyze_directory(self, directory: Path, extensions: tuple = None) -> list[EntropyResult]:
        """Analyze entropy of all files in a directory."""
        results = []
        if extensions is None:
            extensions = (".log", ".txt", ".csv", ".xml", ".json", ".pcap", ".bin", ".dat", "")

        for file_path in sorted(directory.rglob("*")):
            if file_path.is_file():
                if extensions and file_path.suffix.lower() not in extensions and file_path.suffix:
                    continue
                results.append(self.analyze_file(file_path))
        return results

    def analyze_pcap_payloads(self, pcap_path: Path) -> EntropyResult:
        """Analyze entropy of a PCAP or binary payload file."""
        return self.analyze_file(pcap_path, block_size=512)

    def analyze_text_payloads(self, text: str, source_name: str = "") -> EntropyResult:
        """Analyze entropy of text content (e.g., from PCAP DNS/SNI extraction)."""
        result = EntropyResult(file_path=source_name)
        if not text:
            return result

        data = text.encode("utf-8", errors="replace")
        result.file_size = len(data)
        result.overall_entropy = self.compute_entropy(data)
        result.classification = self.classify_entropy(result.overall_entropy)
        result.exfil_risk = result.overall_entropy >= HIGH_ENTROPY_THRESHOLD
        return result
