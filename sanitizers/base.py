import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class Detection:
    entity_type: str
    original_value: str
    start: int
    end: int
    score: float
    page_or_line: Optional[str] = None
    token: Optional[str] = None  # assigned token e.g. [PERSON_1]
    redact: bool = True           # user can uncheck this in GUI


@dataclass
class SanitizeResult:
    source_path: Path
    output_path: Optional[Path] = None
    detections: list[Detection] = field(default_factory=list)
    vault_path: Optional[Path] = None
    error: Optional[str] = None

    @property
    def success(self) -> bool:
        return self.error is None


def dedup_detections(detections: list["Detection"]) -> list["Detection"]:
    """
    Remove overlapping detections within the same page_or_line context,
    keeping the highest-score one per span.
    """
    from collections import defaultdict
    groups: dict = defaultdict(list)
    for d in detections:
        groups[d.page_or_line].append(d)

    result: list[Detection] = []
    for group in groups.values():
        candidates = sorted(group, key=lambda d: (-d.score, d.start))
        kept: list[Detection] = []
        for d in candidates:
            if not any(d.start < k.end and d.end > k.start for k in kept):
                kept.append(d)
        result.extend(kept)

    result.sort(key=lambda d: (d.page_or_line or "", d.start))
    return result


_LEGAL_SUFFIX_RE = re.compile(
    r'\s+(?:ASA|ANS|IKS|DA|BA|SA|NUF|SE|KF|FKF|AS)\s*$',
    re.IGNORECASE,
)


def extract_company_roots(detections: list["Detection"]) -> list[str]:
    """Return unique base names from NORWEGIAN_COMPANY detections (suffix stripped)."""
    roots = set()
    for d in detections:
        if d.entity_type == "NORWEGIAN_COMPANY":
            base = _LEGAL_SUFFIX_RE.sub("", d.original_value).strip()
            if len(base) >= 3:
                roots.add(base)
    return list(roots)


def find_company_root_hits(text: str, roots: list[str], context: str) -> list["Detection"]:
    """Find bare occurrences of company roots (e.g. 'Sicra' in 'Sicra-Antiphish')."""
    hits = []
    for root in roots:
        for m in re.finditer(re.escape(root), text, re.IGNORECASE):
            hits.append(Detection(
                entity_type="NORWEGIAN_COMPANY",
                original_value=text[m.start():m.end()],
                start=m.start(),
                end=m.end(),
                score=0.70,
                page_or_line=context,
            ))
    return hits


class Sanitizer(ABC):
    def __init__(self, path: Path):
        self.path = Path(path)

    @abstractmethod
    def detect(
        self,
        custom_terms: tuple[str, ...] = (),
        enabled_entities: frozenset[str] | None = None,
    ) -> list[Detection]:
        """Return all detections without modifying the file."""

    @abstractmethod
    def sanitize(
        self,
        detections: list[Detection],
        output_path: Path,
        session,  # vault.vault.SanitizeSession
    ) -> SanitizeResult:
        """Apply redactions and write to output_path."""
