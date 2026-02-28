from __future__ import annotations
import threading
from functools import lru_cache
from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
from presidio_analyzer.nlp_engine import NlpEngineProvider

ENABLED_ENTITIES = [
    "PERSON",
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "IP_ADDRESS",
    "URL",
    "CREDIT_CARD",
    "IBAN_CODE",
    "LOCATION",
    "NRP",
    # custom cloud / infrastructure
    "AWS_ACCESS_KEY",
    "AWS_ARN",
    "AWS_ACCOUNT_ID",
    "AZURE_CONNECTION_STRING",
    "AZURE_CLIENT_SECRET",
    "AZURE_UUID",
    "AZURE_SAS_TOKEN",
    "JWT_BEARER_TOKEN",
    "CERTIFICATE_THUMBPRINT",
    "AZURE_RESOURCE_ID",
    "AZURE_TENANT_DOMAIN",
    "AZURE_RESOURCE_NAME",
    "M365_TENANT_URL",
    "GCP_SERVICE_ACCOUNT",
    "GCP_API_KEY",
    "GENERIC_SECRET",
    "INTERNAL_HOSTNAME",
    "PRIVATE_IP",
    "NORWEGIAN_COMPANY",
    "NORWEGIAN_ORG_NUMBER",
    "FILE_PATH",
    # DANGEROUS_FORMULA is injected directly by _XlsxHandler (not via Presidio);
    # kept here so the GUI can display/toggle formula warnings.
    "DANGEROUS_FORMULA",
    # Norwegian person names (NER supplement for en_core_web_lg gaps)
    "NORWEGIAN_PERSON_NAME",
    # Norwegian GDPR — regular identifiers
    "NORWEGIAN_NATIONAL_ID",
    "NORWEGIAN_D_NUMBER",
    "NORWEGIAN_BANK_ACCOUNT",
    "NORWEGIAN_PHONE",
    "NORWEGIAN_POSTAL_ADDRESS",
    "NORWEGIAN_PASSPORT",
    "NORWEGIAN_VEHICLE_REG",
    # Norwegian GDPR — Art. 9 special categories
    "HEALTH_DATA",
    "BIOMETRIC_DATA",
    "GENETIC_DATA",
    "POLITICAL_OPINION",
    "RELIGIOUS_BELIEF",
    "SEXUAL_ORIENTATION",
    "RACIAL_ETHNIC_ORIGIN",
    "TRADE_UNION",
    "CUSTOM_TERM",
]


_analyzer_lock = threading.Lock()


@lru_cache(maxsize=1)
def _build_analyzer(custom_terms: tuple[str, ...] = ()) -> AnalyzerEngine:
    """Build and cache an AnalyzerEngine. Called under _analyzer_lock."""
    from detectors.cloud_secrets import build_cloud_recognizers
    from detectors.norway_gdpr import build_norway_gdpr_recognizers
    from detectors.norwegian_names import build_norwegian_name_recognizers
    from detectors.custom_terms import build_custom_term_recognizer

    from utils.spacy_loader import get_spacy_model_name
    provider = NlpEngineProvider(nlp_configuration={
        "nlp_engine_name": "spacy",
        "models": [{"lang_code": "en", "model_name": get_spacy_model_name()}],
    })
    nlp_engine = provider.create_engine()

    registry = RecognizerRegistry()
    registry.load_predefined_recognizers(nlp_engine=nlp_engine)

    for recognizer in build_cloud_recognizers():
        registry.add_recognizer(recognizer)

    for recognizer in build_norway_gdpr_recognizers():
        registry.add_recognizer(recognizer)

    for recognizer in build_norwegian_name_recognizers():
        registry.add_recognizer(recognizer)

    if custom_terms:
        registry.add_recognizer(build_custom_term_recognizer(list(custom_terms)))

    return AnalyzerEngine(registry=registry, nlp_engine=nlp_engine)


def get_analyzer(custom_terms: tuple[str, ...] = ()) -> AnalyzerEngine:
    """Return cached AnalyzerEngine (thread-safe)."""
    with _analyzer_lock:
        return _build_analyzer(custom_terms)


# ---------------------------------------------------------------------------
# Norwegian false-positive suppression for spaCy en_core_web_lg
# ---------------------------------------------------------------------------
# spaCy's English NER model frequently misclassifies common Norwegian words
# and phrases as PERSON, NRP, or LOCATION.
#
# Strategy:
#   PERSON / NRP  — cross-reference with our SSB name databases (5 600+ names).
#                   Only keep the detection if the span contains at least one
#                   word that is a known Norwegian/Scandinavian name.  This avoids
#                   the impossible task of enumerating every Norwegian common word.
#   LOCATION / NORWEGIAN_COMPANY — use a proper-noun heuristic (the common-word
#                   list is good enough for non-person entities).

# Entity types that use the *proper-noun heuristic* (common-word list)
_HEURISTIC_ENTITY_TYPES = {"LOCATION", "NORWEGIAN_COMPANY"}
# Entity types that require a *known name* from our SSB databases
_NAME_CHECK_ENTITY_TYPES = {"PERSON", "NRP"}

_NORWEGIAN_COMMON_WORDS: frozenset[str] = frozenset({
    # --- pronouns ---
    "jeg", "du", "han", "hun", "den", "det", "vi", "dere", "de",
    "meg", "deg", "seg", "oss", "dem", "ham", "henne",
    "min", "mitt", "mine", "din", "ditt", "dine",
    "sin", "sitt", "sine", "vår", "vårt", "våre",
    "deres", "hans", "hennes",
    "denne", "dette", "disse", "slik", "slikt", "slike",
    "selv", "hverandre", "noe", "noen", "ingen", "ingenting",
    "alt", "alle", "hver", "annet", "andre", "annen",
    "hva", "hvem", "hvilken", "hvilket", "hvilke",
    # --- determiners / articles ---
    "en", "et", "ei",
    # --- prepositions ---
    "i", "på", "til", "fra", "av", "med", "for", "om", "etter",
    "over", "under", "ved", "mellom", "mot", "hos", "blant",
    "gjennom", "langs", "rundt", "siden", "uten", "ifølge",
    "innenfor", "utenfor", "overfor", "innen",
    # --- conjunctions ---
    "og", "eller", "men", "så", "at", "hvis", "når", "da",
    "fordi", "siden", "enn", "enten", "verken", "både",
    "dersom", "likevel", "imidlertid", "dessuten", "altså",
    # --- particles / infinitive marker ---
    "å",
    # --- common verbs (infinitive, present, past, participle) ---
    "er", "var", "vært", "være",
    "har", "hadde", "hatt", "ha",
    "skal", "skulle", "vil", "ville",
    "kan", "kunne", "må", "måtte",
    "bli", "blir", "ble", "blitt",
    "gjøre", "gjør", "gjorde", "gjort",
    "si", "sier", "sa", "sagt",
    "komme", "kommer", "kom", "kommet",
    "gå", "går", "gikk", "gått",
    "se", "ser", "så", "sett",
    "ta", "tar", "tok", "tatt",
    "få", "får", "fikk", "fått",
    "gi", "gir", "gav", "ga", "gitt",
    "vite", "vet", "visste", "visst",
    "finne", "finner", "fant", "funnet",
    "holde", "holder", "holdt",
    "stå", "står", "sto", "stod", "stått",
    "ligge", "ligger", "lå", "ligget",
    "sitte", "sitter", "satt",
    "legge", "legger", "la", "lagt",
    "lære", "lærer", "lærte", "lært",
    "lese", "leser", "leste", "lest",
    "skrive", "skriver", "skrev", "skrevet",
    "bruke", "bruker", "brukte", "brukt",
    "jobbe", "jobber", "jobbet",
    "snakke", "snakker", "snakket",
    "prøve", "prøver", "prøvd", "prøvde",
    "endre", "endrer", "endret",
    "fortelle", "forteller", "fortalte", "fortalt",
    "kjenne", "kjenner", "kjente", "kjent",
    "mene", "mener", "mente", "ment",
    "tro", "tror", "trodde", "trodd",
    "tenke", "tenker", "tenkte", "tenkt",
    "høre", "hører", "hørte", "hørt",
    "spørre", "spør", "spurte", "spurt",
    "svare", "svarer", "svarte", "svart",
    "begynne", "begynner", "begynte", "begynt",
    "slutte", "slutter", "sluttet",
    "åpne", "åpner", "åpnet",
    "lukke", "lukker", "lukket",
    "sende", "sender", "sendte", "sendt",
    "hjelpe", "hjelper", "hjalp", "hjulpet",
    "følge", "følger", "fulgte", "fulgt",
    "virke", "virker", "virket",
    "handle", "handler", "handlet",
    "informere", "informerer", "informerte", "informert",
    "modernisere", "moderniserer", "moderniserte", "modernisert",
    "skje", "skjer", "skjedde", "skjedd",
    "sette", "setter", "settes", "satte",
    "hente", "henter", "hentet",
    "vise", "viser", "viste", "vist",
    "trenge", "trenger", "trengte", "trengt",
    "passe", "passer", "passet",
    "fungere", "fungerer", "fungerte", "fungert",
    "påvirke", "påvirker", "påvirket",
    "oppdatere", "oppdaterer", "oppdatert",
    "forbedre", "forbedrer", "forbedret",
    "diskutere", "diskuterer", "diskuterte", "diskutert",
    # --- adverbs ---
    "ikke", "også", "bare", "jo", "nå", "her", "der",
    "ennå", "allerede", "aldri", "alltid", "ofte", "kanskje",
    "vel", "nok", "hvor", "hvordan", "hvorfor", "helt",
    "ganske", "veldig", "svært", "litt", "mye", "mer", "mest",
    "lite", "mindre", "minst", "godt", "bedre", "best",
    "fort", "snart", "lenge", "straks", "igjen", "ellers",
    "heller", "dessverre", "faktisk", "egentlig", "tydeligvis",
    "akkurat", "nettopp", "deretter", "tidligere", "videre",
    "inne", "ute", "oppe", "nede", "borte", "fremover",
    # --- adjectives ---
    "ny", "nytt", "nye", "god", "godt", "gode",
    "stor", "stort", "store", "liten", "lite", "små",
    "gammel", "gammelt", "gamle", "ung", "ungt", "unge",
    "lang", "langt", "lange", "kort", "korte",
    "enig", "enige", "viktig", "viktige",
    "klar", "klart", "klare", "ferdig", "ferdige",
    "riktig", "riktige", "feil", "greit",
    "annerledes", "forskjellig", "forskjellige",
    "mulig", "umulig",
    "slik", "slikt", "slike", "sånn", "sånne", "sånt",
    # --- ordinals / numerals ---
    "første", "andre", "tredje", "fjerde", "femte",
    "sjette", "syvende", "åttende", "niende", "tiende",
    "siste", "forrige", "neste",
    # --- common nouns (non-name) ---
    "ting", "sak", "saken", "del", "deler",
    "gang", "ganger", "tid", "tiden", "dag", "dagen",
    "rutine", "rutiner", "rutinene",
    "beskjed", "grunn", "grunner", "måte", "måten",
    "folk", "flere", "mange", "masse",
    "arbeid", "jobb", "møte", "møtet",
    "informasjon", "lusning", "system", "prosjekt",
    "tilgang", "tilgangen", "sjef", "sjefen", "sjefene",
    "uke", "uken", "tips", "tipset",
    # --- interjections / fillers ---
    "ja", "nei", "ok", "hei", "takk", "bra",
    # --- labels / field names ---
    "fødselsnummer", "d-nummer", "kontonummer", "adresse", "telefon",
    "kontaktperson", "navn", "epost", "e-post", "passord", "brukernavn",
    # --- patient / medical context ---
    "pasienten", "pasient", "behandling", "diagnose", "lege", "sykehus",
    # --- body / biometric ---
    "fingeravtrykk", "ansikt", "iris", "biometri",
    # --- document / report words ---
    "prosjektrapport", "rapport", "notat", "dokument", "vedlegg", "oversikt",
    "konfidensielt", "internt", "eksternt",
    # --- org/role words ---
    "kunde", "leverandør", "ansatt", "arbeidsgiver", "arbeidstaker",
    "direktør", "leder", "ansvarlig",
})


_CHUNK_SIZE = 80_000   # chars — well under spaCy's 1M limit; overlap avoids split-boundary misses
_CHUNK_OVERLAP = 200


import re as _re
_WORD_RE = _re.compile(r"[A-Za-zÆØÅæøåÀ-ÿ]+")


# ---------------------------------------------------------------------------
# Name-database cross-reference for PERSON / NRP suppression
# ---------------------------------------------------------------------------
_cached_name_sets: tuple[frozenset[str], frozenset[str], frozenset[str]] | None = None


def _get_name_sets() -> tuple[frozenset[str], frozenset[str], frozenset[str]]:
    """Lazy-load the SSB name sets (cached after first call)."""
    global _cached_name_sets
    if _cached_name_sets is None:
        from detectors.norwegian_names import _load_name_set
        _cached_name_sets = (
            _load_name_set("norwegian_first_names.txt"),
            _load_name_set("norwegian_surnames.txt"),
            _load_name_set("scandinavian_extra_names.txt"),
        )
    return _cached_name_sets


def _is_known_name(word: str, first_names, surnames, extra_names) -> bool:
    return word in first_names or word in surnames or word in extra_names


def _extract_name_spans(text: str, r):
    """Trim a PERSON/NRP span to only the name-containing portions.

    spaCy often wraps common words around a name ("Tore har sagt").
    This function extracts groups of consecutive capitalized words that
    contain at least one known name (3+ chars) and returns new
    RecognizerResult(s) covering only those groups.

    Example: "jo Tore og Raimo noe" → ["Tore", "Raimo"] (two results)
    """
    from presidio_analyzer import RecognizerResult
    first_names, surnames, extra_names = _get_name_sets()
    span_text = text[r.start:r.end]

    # Collect capitalized tokens that are NOT common Norwegian words.
    # "Ikke Tore" → skip "Ikke" (common word), keep "Tore".
    cap_tokens: list[tuple[str, int, int]] = []
    for m in _WORD_RE.finditer(span_text):
        word = m.group()
        if word[0].isupper() and word.lower() not in _NORWEGIAN_COMMON_WORDS:
            cap_tokens.append((word, m.start(), m.end()))

    if not cap_tokens:
        return []

    # Group consecutive capitalized words (separated by whitespace only, max 3 chars gap)
    groups: list[list[tuple[str, int, int]]] = []
    current = [cap_tokens[0]]
    for i in range(1, len(cap_tokens)):
        _, _, prev_end = current[-1]
        _, curr_start, _ = cap_tokens[i]
        between = span_text[prev_end:curr_start]
        if between.strip() == "" and len(between) <= 3:
            current.append(cap_tokens[i])
        else:
            groups.append(current)
            current = [cap_tokens[i]]
    groups.append(current)

    # Emit a result for each group that contains a known name (3+ chars)
    results = []
    for group in groups:
        if any(len(w) >= 3 and _is_known_name(w, first_names, surnames, extra_names)
               for w, _, _ in group):
            group_start = r.start + group[0][1]
            group_end = r.start + group[-1][2]
            results.append(RecognizerResult(
                entity_type=r.entity_type,
                start=group_start,
                end=group_end,
                score=r.score,
            ))
    return results


def _looks_like_common_text(span: str) -> bool:
    """Return True (suppress) if the span contains no proper-noun-looking words.

    Used for LOCATION / NORWEGIAN_COMPANY filtering (not PERSON/NRP).
    A proper noun must be capitalised, 3+ chars, and NOT a common Norwegian word.
    """
    words = _WORD_RE.findall(span)
    if not words:
        return True
    if all(w.lower() in _NORWEGIAN_COMMON_WORDS for w in words):
        return True
    for word in words:
        if (len(word) >= 3
                and word[0].isupper()
                and word.lower() not in _NORWEGIAN_COMMON_WORDS):
            return False  # found a likely proper noun → keep detection
    return True  # no proper nouns → suppress


# Norwegian company legal-form suffixes.  Presidio runs the NORWEGIAN_COMPANY
# regex with re.IGNORECASE, so lowercase "da" or "sa" in ordinary text can
# match.  We post-check that the suffix is UPPERCASE in the original text.
_COMPANY_SUFFIXES = {"ASA", "ANS", "IKS", "NUF", "FKF", "ENK",
                     "AS", "DA", "SA", "BA", "KS", "SF", "SE", "STI", "KF"}
_SUFFIX_RE = _re.compile(
    r"(?:" + "|".join(sorted(_COMPANY_SUFFIXES, key=len, reverse=True)) + r")\s*$"
)


def _company_suffix_is_uppercase(span: str) -> bool:
    """Return True if the company suffix at the end of the span is uppercase."""
    m = _SUFFIX_RE.search(span)
    if not m:
        return False
    return m.group().strip() in _COMPANY_SUFFIXES  # exact case match


def _analyze_chunk(analyzer, text: str, entities: list[str]) -> list:
    results = analyzer.analyze(
        text=text,
        language="en",
        entities=entities,
        return_decision_process=False,
    )
    filtered = []
    for r in results:
        if r.entity_type in _NAME_CHECK_ENTITY_TYPES:
            # PERSON / NRP: trim span to name-only portions (may yield 0..N results)
            filtered.extend(_extract_name_spans(text, r))
        elif r.entity_type == "NORWEGIAN_COMPANY":
            span = text[r.start:r.end]
            # Require the suffix (AS, DA, etc.) to be UPPERCASE in the original text
            if not _company_suffix_is_uppercase(span):
                continue
            if _looks_like_common_text(span):
                continue
            filtered.append(r)
        elif r.entity_type in _HEURISTIC_ENTITY_TYPES:
            # LOCATION: use proper-noun heuristic
            span = text[r.start:r.end].strip()
            if _looks_like_common_text(span):
                continue
            filtered.append(r)
        else:
            filtered.append(r)
    return filtered


def analyze_text(
    text: str,
    custom_terms: tuple[str, ...] = (),
    enabled_entities: frozenset[str] | None = None,
) -> list:
    """Convenience wrapper. Splits large texts into chunks to stay within spaCy's max_length."""
    from presidio_analyzer import RecognizerResult
    if enabled_entities is not None:
        if not enabled_entities:
            return []
        entities = list(enabled_entities)
    else:
        entities = ENABLED_ENTITIES
    # DANGEROUS_FORMULA has no Presidio recognizer (injected directly by _XlsxHandler);
    # always exclude it to suppress "no recognizer" warnings on every scan.
    if "DANGEROUS_FORMULA" in entities:
        entities = [e for e in entities if e != "DANGEROUS_FORMULA"]
    # CUSTOM_TERM only exists in the registry when custom_terms are provided;
    # remove it from the entity list when there are no terms to avoid Presidio ValueError.
    if not custom_terms and "CUSTOM_TERM" in entities:
        entities = [e for e in entities if e != "CUSTOM_TERM"]
    if not entities:
        return []
    analyzer = get_analyzer(custom_terms)
    if len(text) <= _CHUNK_SIZE:
        return _analyze_chunk(analyzer, text, entities)

    results = []
    seen: set[tuple[int, int, str]] = set()
    offset = 0
    while offset < len(text):
        end = min(offset + _CHUNK_SIZE, len(text))
        # Try to break on a newline near the end of the chunk
        if end < len(text):
            nl = text.rfind("\n", offset + _CHUNK_SIZE // 2, end)
            if nl != -1:
                end = nl + 1
        chunk = text[offset:end]
        for r in _analyze_chunk(analyzer, chunk, entities):
            abs_start = r.start + offset
            abs_end = r.end + offset
            key = (abs_start, abs_end, r.entity_type)
            if key not in seen:
                seen.add(key)
                results.append(RecognizerResult(
                    entity_type=r.entity_type,
                    start=abs_start,
                    end=abs_end,
                    score=r.score,
                ))
        # Advance with overlap so entities spanning chunk boundaries are captured
        offset = end - _CHUNK_OVERLAP if end < len(text) else end
    return results


def invalidate_cache() -> None:
    """Call when custom recognizer config changes."""
    with _analyzer_lock:
        _build_analyzer.cache_clear()
