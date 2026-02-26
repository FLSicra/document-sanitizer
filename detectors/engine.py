from __future__ import annotations
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


@lru_cache(maxsize=1)
def get_analyzer(custom_terms: tuple[str, ...] = ()) -> AnalyzerEngine:
    """Return cached AnalyzerEngine. Pass custom_terms as a tuple for cache key stability."""
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


# Norwegian common words that spaCy en_core_web_lg misclassifies as PERSON/NRP/LOCATION
_NLP_ENTITY_TYPES = {"PERSON", "NRP", "LOCATION", "NORWEGIAN_PERSON_NAME"}
_NORWEGIAN_STOPWORDS = {
    # labels / field names
    "fødselsnummer", "d-nummer", "kontonummer", "adresse", "telefon",
    "kontaktperson", "navn", "epost", "e-post", "passord", "brukernavn",
    # patient / medical context
    "pasienten", "pasient", "behandling", "diagnose", "lege", "sykehus",
    # body / biometric
    "fingeravtrykk", "ansikt", "iris", "biometri",
    # document / report words
    "prosjektrapport", "rapport", "notat", "dokument", "vedlegg", "oversikt",
    "konfidensielt", "internt", "eksternt",
    # org/role words
    "kunde", "leverandør", "ansatt", "arbeidsgiver", "arbeidstaker",
    "direktør", "leder", "ansvarlig",
}


_CHUNK_SIZE = 80_000   # chars — well under spaCy's 1M limit; overlap avoids split-boundary misses
_CHUNK_OVERLAP = 200


def _analyze_chunk(analyzer, text: str, entities: list[str]) -> list:
    results = analyzer.analyze(
        text=text,
        language="en",
        entities=entities,
        return_decision_process=False,
    )
    filtered = []
    for r in results:
        if r.entity_type in _NLP_ENTITY_TYPES:
            matched = text[r.start:r.end].strip().lower()
            if matched in _NORWEGIAN_STOPWORDS:
                continue
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
    get_analyzer.cache_clear()
