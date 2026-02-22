from presidio_analyzer import PatternRecognizer, Pattern
import re


def _term_pattern(t: str) -> str:
    """Wrap escaped term with boundary assertions that work regardless of edge character type."""
    escaped = re.escape(t)
    prefix = r"\b" if re.match(r'^\w', t) else r"(?<!\w)"
    suffix = r"\b" if re.search(r'\w$', t) else r"(?!\w)"
    return prefix + escaped + suffix


def build_custom_term_recognizer(terms: list[str]) -> PatternRecognizer:
    """Build a PatternRecognizer that matches any of the user-supplied deny-list terms."""
    if not terms:
        raise ValueError("terms list must be non-empty")

    pattern = "|".join(_term_pattern(t) for t in terms if t.strip())
    return PatternRecognizer(
        supported_entity="CUSTOM_TERM",
        patterns=[Pattern(
            name="custom_term",
            regex=pattern,
            score=0.99,
        )],
        context=[],
    )
