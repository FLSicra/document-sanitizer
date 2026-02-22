"""
Norwegian GDPR recognizers.

Covers all personal data categories under GDPR as implemented by the Norwegian
Personal Data Act (Personopplysningsloven, LOV-2018-06-15-38), including:
  - Regular identifiers: fødselsnummer, D-nummer, kontonummer, phone, postal address
  - Art. 9 special categories: health, biometric, genetic, political, religious,
    sexual orientation, racial/ethnic origin, trade union membership
"""
import re
from presidio_analyzer import PatternRecognizer, Pattern, EntityRecognizer, RecognizerResult
from presidio_analyzer import AnalysisExplanation


def build_norway_gdpr_recognizers() -> list[PatternRecognizer]:
    return [
        # --- Regular identifiers ---
        _norwegian_national_id(),
        _norwegian_d_number(),
        _norwegian_bank_account(),
        _norwegian_phone(),
        _norwegian_postal_address(),
        _norwegian_passport(),
        _norwegian_vehicle_reg(),
        # --- Art. 9 special categories ---
        _health_data(),
        _biometric_data(),
        _genetic_data(),
        _political_opinion(),
        _religious_belief(),
        _sexual_orientation(),
        _racial_ethnic_origin(),
        _trade_union(),
    ]


# ---------------------------------------------------------------------------
# Regular identifiers
# ---------------------------------------------------------------------------

class _FodselsnummerRecognizer(EntityRecognizer):
    """
    Fødselsnummer recognizer with modulo-11 check digit validation.

    Validated numbers score 0.85 (high confidence).
    Pattern-matched but unvalidated numbers (e.g. intentionally anonymised data)
    score 0.35 so they are still flagged but with low confidence.
    """

    _CONTEXT = [
        "fødselsnummer", "fodselsnummer", "fnr", "personnummer", "personnr",
        "id-nummer", "identifikasjonsnummer", "nasjonalt id", "national id",
        "birth number", "personal number", "f-nummer",
    ]
    _PATTERNS = [
        # DDMMYYIIICCC (plain)
        r"\b(?:0[1-9]|[12]\d|3[01])(?:0[1-9]|1[0-2])\d{7}\b",
        # DDMMYY III CC (spaced)
        r"\b(?:0[1-9]|[12]\d|3[01])(?:0[1-9]|1[0-2])\d{2}\s\d{3}\s\d{2}\b",
    ]

    def __init__(self):
        super().__init__(
            supported_entities=["NORWEGIAN_NATIONAL_ID"],
            name="FodselsnummerRecognizer",
            supported_language="en",
            context=self._CONTEXT,
        )

    def load(self) -> None:
        pass

    def analyze(self, text: str, entities: list, nlp_artifacts=None) -> list:
        results = []
        for pattern in self._PATTERNS:
            for m in re.finditer(pattern, text):
                digits = m.group().replace(" ", "")
                score = 0.85 if self._valid_check_digits(digits) else 0.35
                explanation = AnalysisExplanation(
                    recognizer=self.__class__.__name__,
                    original_score=score,
                    pattern_name="fodselsnummer",
                    pattern=pattern,
                )
                results.append(RecognizerResult(
                    entity_type="NORWEGIAN_NATIONAL_ID",
                    start=m.start(),
                    end=m.end(),
                    score=score,
                    analysis_explanation=explanation,
                ))
        return results

    @staticmethod
    def _valid_check_digits(digits: str) -> bool:
        if len(digits) != 11:
            return False
        d = [int(c) for c in digits]
        w1 = [3, 7, 6, 1, 8, 9, 4, 5, 2]
        s1 = sum(d[i] * w1[i] for i in range(9))
        r1 = s1 % 11
        if r1 == 1:
            return False
        k1 = 0 if r1 == 0 else (11 - r1)
        if d[9] != k1:
            return False
        w2 = [5, 4, 3, 2, 7, 6, 5, 4, 3, 2]
        s2 = sum(d[i] * w2[i] for i in range(10))
        r2 = s2 % 11
        if r2 == 1:
            return False
        k2 = 0 if r2 == 0 else (11 - r2)
        return d[10] == k2


def _norwegian_national_id() -> _FodselsnummerRecognizer:
    """Return a fødselsnummer recognizer with modulo-11 check digit validation."""
    return _FodselsnummerRecognizer()


def _norwegian_d_number() -> PatternRecognizer:
    """
    D-nummer: temporary ID for foreign nationals in Norway.
    Same structure as fødselsnummer but first digit is increased by 4 (day: 41-71).
    """
    return PatternRecognizer(
        supported_entity="NORWEGIAN_D_NUMBER",
        patterns=[Pattern(
            name="d_nummer",
            regex=r"\b(?:4[1-9]|[567]\d)(?:0[1-9]|1[0-2])\d{7}\b",
            score=0.7,
        )],
        context=[
            "d-nummer", "d nummer", "dnummer", "midlertidig id",
            "temporary id", "temporary identification", "d number",
        ],
    )


def _norwegian_bank_account() -> PatternRecognizer:
    """
    Kontonummer: Norwegian domestic bank account number, 11 digits.
    Canonical dotted format: NNNN.NN.NNNNN (highly distinctive).
    Plain 11-digit format boosted by context.
    """
    return PatternRecognizer(
        supported_entity="NORWEGIAN_BANK_ACCOUNT",
        patterns=[
            Pattern(
                name="kontonummer_dotted",
                regex=r"\b\d{4}\.\d{2}\.\d{5}\b",
                score=0.9,
            ),
            Pattern(
                name="kontonummer_plain",
                regex=r"\b\d{11}\b",
                score=0.4,
            ),
        ],
        context=[
            "kontonummer", "konto", "bankkonto", "bank account", "account number",
            "kontonr", "kredittkonto", "lønnskonto", "sparekonto",
        ],
    )


def _norwegian_phone() -> PatternRecognizer:
    """
    Norwegian phone numbers: +47 or 0047 prefix + 8 digits.
    Also bare 8-digit numbers starting with 4 or 9 (mobile) in context.
    """
    return PatternRecognizer(
        supported_entity="NORWEGIAN_PHONE",
        patterns=[
            Pattern(
                name="no_phone_intl",
                regex=r"(?:\+47|0047)\s?\d{4}\s?\d{4}",
                score=0.9,
            ),
            Pattern(
                name="no_phone_mobile_bare",
                regex=r"\b[49]\d{7}\b",
                score=0.5,
            ),
        ],
        context=[
            "telefon", "mobil", "tlf", "phone", "mobile", "cell", "call",
            "ring", "sms", "nummer", "kontakt",
        ],
    )


def _norwegian_postal_address() -> PatternRecognizer:
    """
    Norwegian postal code (4 digits) followed by city/place name.
    Also matches full street address patterns.
    """
    return PatternRecognizer(
        supported_entity="NORWEGIAN_POSTAL_ADDRESS",
        patterns=[
            Pattern(
                name="postnummer_by",
                # 4-digit postal code followed by a capitalised place name (no newlines)
                regex=r"\b\d{4}[ \t]+[A-ZÆØÅ][a-zæøå]{2,}(?:[ \t]+[A-ZÆØÅ][a-zæøå]+)*\b",
                score=0.65,
            ),
            Pattern(
                name="street_address",
                # "Gatenavn 12", "Gatenavn 12 B", "Gatenavn 12b"
                regex=(
                    r"\b[A-ZÆØÅ][a-zæøåA-ZÆØÅ]+(?:gata|gaten|gate|veien|vei|"
                    r"allé|alléen|plass|plassen|torg|torget|stien|sti)"
                    r"\s+\d{1,4}[A-Za-z]?\b"
                ),
                score=0.7,
            ),
        ],
        context=[
            "adresse", "address", "postnummer", "poststed", "postadresse",
            "hjemstedsadresse", "bostedsadresse", "gate", "vei", "gard", "by", "kommune",
        ],
    )


def _norwegian_passport() -> PatternRecognizer:
    """
    Norwegian passport number: 2 uppercase letters followed by 7 digits.
    Norwegian passports are issued in the format e.g. NO123456 or AB1234567.
    """
    return PatternRecognizer(
        supported_entity="NORWEGIAN_PASSPORT",
        patterns=[Pattern(
            name="passport_no",
            regex=r"\b[A-Z]{2}\d{7}\b",
            score=0.5,
        )],
        context=[
            "pass", "passport", "passnummer", "passport number", "reisepass",
            "reisedokument", "travel document",
        ],
    )


def _norwegian_vehicle_reg() -> PatternRecognizer:
    """
    Norwegian vehicle registration plates: 2 letters + 5 digits (e.g. AB 12345).
    Electric vehicles use EL/EK prefix (e.g. EL 12345).
    """
    return PatternRecognizer(
        supported_entity="NORWEGIAN_VEHICLE_REG",
        patterns=[Pattern(
            name="vehicle_plate",
            regex=r"\b[A-ZÆØÅ]{2}\s?\d{5}\b",
            score=0.5,
        )],
        context=[
            "regnr", "registreringsnummer", "bilnummer", "bil", "kjøretøy",
            "plate", "vehicle", "car", "registration", "kjennemerke",
        ],
    )


# ---------------------------------------------------------------------------
# Art. 9 Special Categories
# ---------------------------------------------------------------------------

def _health_data() -> PatternRecognizer:
    """
    GDPR Art. 9 — Data concerning health.
    Flags medical/health terms in Norwegian and English.
    """
    health_terms = (
        # Norwegian
        r"diagnos[ea]|diagnos[ea]r|sykdom|sykdommer|sykdomsbilde|medisin|medisiner"
        r"|resept|behandling|operasjon|innlagt|innleggelse|pasient|helsepersonell"
        r"|lege|sykepleier|psykolog|terapeut|sykehus|klinikk|legekontor|poliklinikk"
        r"|helsetilstand|funksjonshemning|funksjonshemming|uføregrad|arbeidsevne"
        r"|allergi|allergitest|bivirkninger|kronisk|akutt|terminal|palliativ"
        r"|kreft|diabetes|hypertensjon|depresjon|angst|psykose|demens|epilepsi"
        r"|blodtype|vaksine|vaksinasjon|immunitet|journal|pasientjournal|epikrisen"
        r"|henvisning|sykmelding|uføretrygd|rehabilitering|hjelpemiddel"
        # English
        r"|diagnosis|disease|medication|prescription|treatment|surgery|patient"
        r"|physician|nurse|therapist|hospital|clinic|health condition|disability"
        r"|allergy|chronic|terminal|cancer|blood type|vaccine|medical record"
        r"|referral|sick leave|rehabilitation"
    )
    return PatternRecognizer(
        supported_entity="HEALTH_DATA",
        patterns=[Pattern(name="health_term", regex=rf"\b(?:{health_terms})\b", score=0.6)],
        context=[
            "helse", "medisinsk", "klinisk", "health", "medical", "clinical",
            "pasient", "patient", "journal", "record", "behandlende",
        ],
    )


def _biometric_data() -> PatternRecognizer:
    """
    GDPR Art. 9 — Biometric data used for unique identification.
    """
    terms = (
        r"fingeravtrykk|fingeravtrykkscanner|ansiktsgjenkjenning|iris(?:skanning|scan)"
        r"|retinascan|håndgeometri|stemmeavtrykk|stemmegjenkjenning|biometrisk"
        r"|biometriske data|ansiktsscan|ansiktsidentifikasjon"
        r"|fingerprint|facial recognition|iris scan|retinal scan"
        r"|voice recognition|hand geometry|biometric|biometric data"
    )
    return PatternRecognizer(
        supported_entity="BIOMETRIC_DATA",
        patterns=[Pattern(name="biometric_term", regex=rf"\b(?:{terms})\b", score=0.7)],
        context=["identifikasjon", "identification", "autentisering", "authentication", "sikkerhet", "security"],
    )


def _genetic_data() -> PatternRecognizer:
    """
    GDPR Art. 9 — Genetic data.
    """
    terms = (
        r"genetisk(?:\s+test(?:ing)?|\s+profil|\s+data|\s+informasjon|\s+material[ea]?)?"
        r"|genprofil|genomsekvens|DNA-profil|DNA-analyse|DNA-test|kromosomanalyse"
        r"|arvelighet|genetisk disposisjon|genetisk sykdom|mutasjon|genvariant"
        r"|genome|genomic(?:\s+data|\s+profile)?|genetic(?:\s+test(?:ing)?|\s+profile"
        r"|\s+data|\s+information|\s+material)?|DNA\s+(?:profile|analysis|test|sequence)"
        r"|chromosome(?:\s+analysis)?|hereditary|gene\s+variant|mutation"
    )
    return PatternRecognizer(
        supported_entity="GENETIC_DATA",
        patterns=[Pattern(name="genetic_term", regex=rf"(?:{terms})", score=0.75)],
        context=["laboratorium", "laboratory", "analyse", "analysis", "arv", "hereditary", "DNA", "gen"],
    )


def _political_opinion() -> PatternRecognizer:
    """
    GDPR Art. 9 — Political opinions.
    Flags Norwegian party names and political affiliation terms.
    """
    terms = (
        # Norwegian parties
        r"Arbeiderpartiet|Høyre|Fremskrittspartiet|Venstre|Senterpartiet"
        r"|Sosialistisk Venstreparti|Kristelig Folkeparti|Miljøpartiet De Grønne"
        r"|Rødt|Pensjonistpartiet"
        r"|politisk\s+(?:parti|overbevisning|mening|standpunkt|tilhørighet|aktivitet)"
        r"|partimedlem(?:skap)?|stemmerett|politisk\s+orientering"
        # English
        r"|political\s+(?:party|opinion|belief|affiliation|orientation|view)"
        r"|party\s+member(?:ship)?|voting\s+(?:record|preference)"
    )
    return PatternRecognizer(
        supported_entity="POLITICAL_OPINION",
        patterns=[Pattern(name="political_term", regex=rf"(?:{terms})", score=0.65)],
        context=["politikk", "politics", "valg", "election", "parti", "party", "stemme", "vote"],
    )


def _religious_belief() -> PatternRecognizer:
    """
    GDPR Art. 9 — Religious or philosophical beliefs.
    """
    terms = (
        # Norwegian
        r"Den norske kirke|statskirke|frikirke|menighet|gudstjeneste|konfirmant"
        r"|dåp|nattverd|bønn|religiøs\s+(?:tro|overbevisning|tilhørighet|praksis)"
        r"|livssyn|trossamfunn|imam|prest|pastor|rabbi|diakon"
        r"|muslim|kristen|jødisk|buddhistisk|hinduistisk|sikh|ateist|agnostiker"
        r"|moské|synagoge|tempel|kirke\b"
        # English
        r"|religious\s+(?:belief|affiliation|practice)|church\s+member(?:ship)?"
        r"|place\s+of\s+worship|faith\s+community|philosophical\s+belief"
        r"|mosque|synagogue|temple|atheist|agnostic|denomination"
    )
    return PatternRecognizer(
        supported_entity="RELIGIOUS_BELIEF",
        patterns=[Pattern(name="religious_term", regex=rf"(?:{terms})", score=0.65)],
        context=["tro", "faith", "religion", "livssyn", "belief", "kirke", "church"],
    )


def _sexual_orientation() -> PatternRecognizer:
    """
    GDPR Art. 9 — Data concerning sex life or sexual orientation.
    """
    terms = (
        r"seksuell\s+orientering|seksualitet|homofil|lesbisk|bifil|heterofil"
        r"|transperson|kjønnsidentitet|kjønnsuttrykk|ikke-binær|interkjønn"
        r"|LHBT\+?|LGBTQ\+?|pride|homoekteskap|samboer(?:\s+av\s+samme\s+kjønn)?"
        r"|sexual\s+orientation|sexuality|gay|lesbian|bisexual|heterosexual"
        r"|transgender|gender\s+identity|gender\s+expression|non-binary|intersex"
        r"|same.sex\s+(?:partner|relationship|marriage)"
    )
    return PatternRecognizer(
        supported_entity="SEXUAL_ORIENTATION",
        patterns=[Pattern(name="sexual_orientation_term", regex=rf"(?:{terms})", score=0.7)],
        context=["identitet", "identity", "orientering", "orientation", "forhold", "relationship"],
    )


def _racial_ethnic_origin() -> PatternRecognizer:
    """
    GDPR Art. 9 — Racial or ethnic origin.
    """
    terms = (
        # Norwegian
        r"etnisk\s+(?:opprinnelse|bakgrunn|gruppe|minoritet|identitet)"
        r"|rasemessig\s+opprinnelse|nasjonalt\s+minst(?:ett|erier)"
        r"|urfolk|samer|samisk|nasjonale\s+minoriteter|romani|romani-folket|tatere|kvener"
        r"|innvandrerbakgrunn|flyktningbakgrunn|asylsøker|utenlandsk\s+opprinnelse"
        # English
        r"|ethnic\s+(?:origin|background|group|minority|identity)"
        r"|racial\s+origin|national\s+minority|indigenous\s+people"
        r"|immigrant\s+background|refugee\s+background|foreign\s+origin"
    )
    return PatternRecognizer(
        supported_entity="RACIAL_ETHNIC_ORIGIN",
        patterns=[Pattern(name="racial_ethnic_term", regex=rf"(?:{terms})", score=0.65)],
        context=["opprinnelse", "origin", "bakgrunn", "background", "etnisitet", "ethnicity"],
    )


def _trade_union() -> PatternRecognizer:
    """
    GDPR Art. 9 — Trade union membership.
    """
    terms = (
        # Norwegian confederations and major unions (longer names only — short acronyms via context)
        r"Landsorganisasjonen|Akademikerne\b"
        r"|fagforening|fagforbund|fagorganisert|fagorganisasjon"
        r"|tillitsvalgt|arbeidstakerorganisasjon|arbeidsgiverorganisasjon"
        r"|tariffavtale|streik|lockout|faglig\s+(?:representant|tillitsmann)"
        r"|Fellesforbundet|Fagforbundet|Utdanningsforbundet|Sykepleierforbundet"
        r"|NITO\b|Legeforeningen|Juristforbundet|Negotia\b"
        # English
        r"|trade\s+union\s+member(?:ship)?|labor\s+union|union\s+member(?:ship)?"
        r"|collective\s+bargaining|shop\s+steward|union\s+dues"
    )
    return PatternRecognizer(
        supported_entity="TRADE_UNION",
        patterns=[Pattern(name="trade_union_term", regex=rf"(?:{terms})", score=0.7)],
        context=["fagbevegelse", "union", "member", "arbeid", "work", "ansatt", "employee",
                 "LO", "YS", "Unio", "fagorganisert", "tariff"],
    )
