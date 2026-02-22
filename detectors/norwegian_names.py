"""
Norwegian person name recognizers.

Supplements the spaCy en_core_web_lg NER model, which is trained on English text
and frequently misses Norwegian names — particularly those containing the characters
Æ, Ø, and Å, and common Norwegian first names that do not appear in English corpora.
"""
import re
from presidio_analyzer import PatternRecognizer, Pattern

_NORWEGIAN_FIRST_NAMES = [
    "Bjørn", "Ørjan", "Åse", "Sigbjørn", "Oddbjørn", "Torbjørn", "Dagfinn",
    "Asbjørn", "Ragnhild", "Solveig", "Ingeborg", "Gunnhild", "Jorunn",
    "Sigrunn", "Arnfinn", "Hallgeir", "Kjell", "Terje", "Geir", "Svein",
    "Trond", "Magne", "Stein", "Knut", "Gudmund", "Sigurd", "Halvard",
    "Njål", "Eirik", "Leif", "Tore", "Atle", "Frode", "Vidar", "Roar",
    "Ivar", "Arild", "Stig", "Ove", "Bård", "Håkon", "Erling", "Espen",
    "Vegard", "Stian", "Morten", "Jarle", "Rune", "Yngve", "Silje", "Hege",
    "Marit", "Grete", "Turid", "Wenche", "Berit", "Torill", "Bente", "Liv",
    "Inger", "Unni", "Astrid", "Gunvor", "Eldbjørg", "Hildegunn", "Magnhild",
    "Torild", "Borgny", "Gerd", "Randi", "Siri", "Trine", "Hilde", "Anita",
    "Mona", "Heidi", "Vigdis", "Kristin",
]


def build_norwegian_name_recognizers() -> list[PatternRecognizer]:
    return [
        _norwegian_name_aao(),
        _norwegian_common_names(),
    ]


def _norwegian_name_aao() -> PatternRecognizer:
    """
    Detects Norwegian names that contain ÆØÅ characters.

    en_core_web_lg (an English model) treats words with these characters as
    out-of-vocabulary tokens and frequently fails to classify them as PERSON.
    This pattern matches a capitalised word containing ÆØÅ followed by a
    capitalised word (likely a surname).
    """
    return PatternRecognizer(
        supported_entity="NORWEGIAN_PERSON_NAME",
        patterns=[Pattern(
            name="norwegian_name_aao",
            regex=r"[A-ZÆØÅ][a-zæøå]*[æøåÆØÅ][a-zæøå]*\s+[A-ZÆØÅ][a-zæøå]+",
            score=0.6,
        )],
    )


def _norwegian_common_names() -> PatternRecognizer:
    """
    Detects common distinctly Norwegian first names followed by a capitalised surname.

    These names are absent from English training corpora, so spaCy en_core_web_lg
    consistently fails to tag them as PERSON entities.  Context words (ansatt,
    bruker, kontakt, etc.) raise the score via Presidio's context enhancement.
    """
    names_pattern = "|".join(re.escape(name) for name in _NORWEGIAN_FIRST_NAMES)
    return PatternRecognizer(
        supported_entity="NORWEGIAN_PERSON_NAME",
        patterns=[Pattern(
            name="norwegian_common_first_name",
            regex=rf"\b(?:{names_pattern})\s+[A-ZÆØÅ][a-zæøå]+\b",
            score=0.65,
        )],
        context=["navn", "name", "ansatt", "employee", "bruker", "user", "kontakt", "contact"],
    )
