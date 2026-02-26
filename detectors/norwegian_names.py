"""
Norwegian and Scandinavian person name recognizers.

Supplements the spaCy en_core_web_lg NER model, which is trained on English text
and frequently misses Norwegian names — particularly those containing the characters
Æ, Ø, and Å, and common Norwegian/Scandinavian first names absent from English corpora.

Name data is sourced from SSB (Statistics Norway) public statistics:
  - Table 10467: Norwegian first names (1880–2025)
  - Table 12891: Norwegian surnames used by 200+ people
  - Curated Scandinavian extras: common Swedish/Danish names

Detection uses set-based lookup (O(n) in text length) rather than regex alternation
(which would be O(n*m) with thousands of names).
"""
from __future__ import annotations

import re
import sys
from functools import lru_cache
from pathlib import Path

from presidio_analyzer import (
    AnalysisExplanation,
    EntityRecognizer,
    PatternRecognizer,
    Pattern,
    RecognizerResult,
)


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def _data_dir() -> Path:
    """Resolve data/ directory for both normal and PyInstaller-frozen execution."""
    if getattr(sys, "frozen", False):
        return Path(sys._MEIPASS) / "data"
    return Path(__file__).resolve().parent.parent / "data"


@lru_cache(maxsize=4)
def _load_name_set(filename: str) -> frozenset[str]:
    """Load names from a text file, one per line. Returns frozenset for O(1) lookup."""
    path = _data_dir() / filename
    if not path.exists():
        return frozenset()
    names: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        name = line.strip()
        if name and not name.startswith("#"):
            names.add(name)
    return frozenset(names)


# ---------------------------------------------------------------------------
# Custom EntityRecognizer — set-based lookup
# ---------------------------------------------------------------------------

# Capitalized-word tokenizer (includes ÆØÅ and hyphenated/apostrophe names)
_TOKEN_RE = re.compile(r"\b[A-ZÆØÅ][a-zæøåA-ZÆØÅ''‑-]+\b")

# Very short words (<=2 chars) that are common Norwegian words, not names.
# These are suppressed from standalone detection to avoid false positives.
_AMBIGUOUS_SHORT: frozenset[str] = frozenset({
    "Av", "Da", "De", "Di", "Ei", "En", "Er", "Et",
    "Ja", "Li", "Mo", "Og", "Os", "På", "Ut", "Vi",
})


class _NorwegianNameRecognizer(EntityRecognizer):
    """
    High-performance Norwegian name recognizer using set-based lookup.

    Tokenizes text into capitalized words and checks them against known
    Norwegian first names and surnames sourced from SSB (Statistics Norway),
    plus curated Scandinavian extras (Swedish/Danish).

    Scoring tiers (before Presidio context boost):
      Known first name + known surname adjacent:  0.85
      Known first name + any capitalized word:     0.70
      Any capitalized word + known surname:        0.70
      Standalone known first name (3+ chars):      0.50
      Standalone known surname (3+ chars):         0.50

    Context words raise scores via Presidio's built-in context enhancement.
    """

    CONTEXT = [
        "navn", "name", "ansatt", "employee", "bruker", "user",
        "kontakt", "contact", "person", "kollega", "pasient",
        "klient", "client", "deltaker", "participant",
        "innringer", "caller", "intervjuobjekt", "respondent",
    ]

    def __init__(self):
        super().__init__(
            supported_entities=["NORWEGIAN_PERSON_NAME"],
            name="NorwegianNameRecognizer",
            supported_language="en",
            context=self.CONTEXT,
        )
        self._first_names: frozenset[str] | None = None
        self._surnames: frozenset[str] | None = None
        self._extra_names: frozenset[str] | None = None

    def load(self) -> None:
        self._first_names = _load_name_set("norwegian_first_names.txt")
        self._surnames = _load_name_set("norwegian_surnames.txt")
        self._extra_names = _load_name_set("scandinavian_extra_names.txt")

    def _ensure_loaded(self):
        if self._first_names is None:
            self.load()

    def _is_first_name(self, word: str) -> bool:
        return word in self._first_names or word in self._extra_names

    def analyze(self, text: str, entities: list, nlp_artifacts=None) -> list:
        self._ensure_loaded()
        results: list[RecognizerResult] = []

        # Find all capitalized tokens with positions
        tokens = [(m.group(), m.start(), m.end()) for m in _TOKEN_RE.finditer(text)]

        # Track indices already consumed as part of a pair (to avoid duplicates)
        consumed: set[int] = set()

        for i, (word, start, end) in enumerate(tokens):
            if i in consumed:
                continue

            is_first = self._is_first_name(word)
            is_surname = word in self._surnames

            # Check if next token is adjacent (only whitespace, max 3 chars gap)
            next_adjacent = False
            next_word = next_start = next_end = None
            if i + 1 < len(tokens):
                next_word, next_start, next_end = tokens[i + 1]
                between = text[end:next_start]
                if between.strip() == "" and len(between) <= 3:
                    next_adjacent = True

            if is_first and next_adjacent:
                next_is_surname = next_word in self._surnames
                next_is_first = self._is_first_name(next_word)

                if next_is_surname:
                    # Known first + known surname → high confidence
                    results.append(self._result(start, next_end, 0.85, "first_surname_pair"))
                    consumed.add(i + 1)
                    continue
                elif not next_is_first:
                    # Known first + unknown capitalized word (likely surname)
                    results.append(self._result(start, next_end, 0.70, "first_plus_capitalized"))
                    consumed.add(i + 1)
                    continue

            # Check if previous token makes this a "capitalized + known surname" pair
            if is_surname and not is_first:
                prev_adjacent = False
                if i > 0 and (i - 1) not in consumed:
                    prev_word, prev_start, prev_end = tokens[i - 1]
                    between_prev = text[prev_end:start]
                    if between_prev.strip() == "" and len(between_prev) <= 3:
                        prev_adjacent = True
                        prev_is_first = self._is_first_name(prev_word)

                        if prev_is_first:
                            # Already handled in the previous iteration
                            pass
                        elif prev_word not in self._surnames:
                            # Unknown capitalized word + known surname
                            results.append(self._result(prev_start, end, 0.70, "capitalized_plus_surname"))
                            consumed.add(i - 1)
                            consumed.add(i)
                            continue

            # Standalone detection (aggressive)
            if word in _AMBIGUOUS_SHORT or len(word) < 3:
                continue

            if is_first:
                results.append(self._result(start, end, 0.50, "standalone_first_name"))
            elif is_surname:
                results.append(self._result(start, end, 0.50, "standalone_surname"))

        return results

    @staticmethod
    def _result(start: int, end: int, score: float, pattern_name: str) -> RecognizerResult:
        return RecognizerResult(
            entity_type="NORWEGIAN_PERSON_NAME",
            start=start,
            end=end,
            score=score,
            analysis_explanation=AnalysisExplanation(
                recognizer="NorwegianNameRecognizer",
                original_score=score,
                pattern_name=pattern_name,
                pattern="set_lookup",
            ),
        )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_norwegian_name_recognizers() -> list:
    """Return all Norwegian/Scandinavian name recognizers."""
    return [
        _NorwegianNameRecognizer(),
    ]
