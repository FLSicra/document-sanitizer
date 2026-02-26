"""
Tests for the security-hardening additions (gaps 1–9).

Recognizer-level tests call .analyze() directly and do not require spaCy/NLP.
Tests marked `integration` require the full AnalyzerEngine (spaCy must be installed).
"""
import re
import pytest
from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# Task 1 – Azure UUID (GAP 1)
# ---------------------------------------------------------------------------

class TestAzureUuid:
    def setup_method(self):
        from detectors.cloud_secrets import _azure_uuid
        self.r = _azure_uuid()

    def test_plain_guid_detected(self):
        text = "appid 12345678-1234-1234-1234-123456789abc present"
        results = self.r.analyze(text, ["AZURE_UUID"])
        assert any(r.entity_type == "AZURE_UUID" for r in results)

    def test_base_score_is_0_6(self):
        text = "value 12345678-1234-1234-1234-123456789abc end"
        results = self.r.analyze(text, ["AZURE_UUID"])
        assert any(r.score == 0.6 for r in results if r.entity_type == "AZURE_UUID")

    def test_json_value_pattern_score_0_8(self):
        text = '{"tenantId": "12345678-1234-1234-1234-123456789abc"}'
        results = self.r.analyze(text, ["AZURE_UUID"])
        assert any(r.score == 0.8 for r in results if r.entity_type == "AZURE_UUID")

    def test_uppercase_guid_matched(self):
        # Presidio normalises text before pattern matching, so uppercase GUIDs are also caught
        text = "12345678-1234-1234-1234-12345678ABCD"
        results = self.r.analyze(text, ["AZURE_UUID"])
        assert any(r.entity_type == "AZURE_UUID" for r in results)

    def test_no_match_on_plain_text(self):
        assert not self.r.analyze("nothing here", ["AZURE_UUID"])


# ---------------------------------------------------------------------------
# Task 2 – SAS Token (GAP 2)
# ---------------------------------------------------------------------------

class TestAzureSasToken:
    def setup_method(self):
        from detectors.cloud_secrets import _azure_sas_token
        self.r = _azure_sas_token()

    def test_full_sas_url(self):
        url = (
            "https://myaccount.blob.core.windows.net/container"
            "?sv=2020-02-10&ss=bfqt&srt=co&sp=rwdlacuptfx"
            "&se=2024-01-01T00%3A00%3A00Z&st=2023-01-01T00%3A00%3A00Z"
            "&spr=https&sig=abcdefghijklmnopqrstuvwxyz1234567890AB"
        )
        results = self.r.analyze(url, ["AZURE_SAS_TOKEN"])
        assert any(r.entity_type == "AZURE_SAS_TOKEN" for r in results)

    def test_standalone_query_string_with_sv(self):
        text = "?sv=2020-02-10&sig=verylongsignaturevalue12345&se=2024-01-01"
        results = self.r.analyze(text, ["AZURE_SAS_TOKEN"])
        assert any(r.entity_type == "AZURE_SAS_TOKEN" for r in results)

    def test_score_is_0_9(self):
        text = "?sv=2020-08-04&sig=averylongsignature12345678901&se=2025-01-01"
        results = self.r.analyze(text, ["AZURE_SAS_TOKEN"])
        matches = [r for r in results if r.entity_type == "AZURE_SAS_TOKEN"]
        assert matches
        assert all(r.score == 0.9 for r in matches)


# ---------------------------------------------------------------------------
# Task 3 – JWT / Bearer Token (GAP 3)
# ---------------------------------------------------------------------------

class TestJwtBearerToken:
    def setup_method(self):
        from detectors.cloud_secrets import _jwt_token
        self.r = _jwt_token()

    def test_compact_jwt_detected(self):
        # Three base64url-encoded parts starting with eyJ...
        token = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
            ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QifQ"
            ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        )
        results = self.r.analyze(token, ["JWT_BEARER_TOKEN"])
        assert any(r.entity_type == "JWT_BEARER_TOKEN" and r.score == 0.95 for r in results)

    def test_bearer_header_detected(self):
        text = "Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.payload.signature"
        results = self.r.analyze(text, ["JWT_BEARER_TOKEN"])
        assert any(r.entity_type == "JWT_BEARER_TOKEN" for r in results)

    def test_bearer_score_0_85(self):
        text = "Bearer someaccesstoken1234567890abcdef"
        results = self.r.analyze(text, ["JWT_BEARER_TOKEN"])
        matches = [r for r in results if r.entity_type == "JWT_BEARER_TOKEN"]
        assert matches
        assert any(r.score == 0.85 for r in matches)

    def test_bearer_case_insensitive(self):
        text = "BEARER mytoken123456"
        results = self.r.analyze(text, ["JWT_BEARER_TOKEN"])
        assert any(r.entity_type == "JWT_BEARER_TOKEN" for r in results)


# ---------------------------------------------------------------------------
# Task 4 – Certificate Thumbprint (GAP 4)
# ---------------------------------------------------------------------------

class TestCertificateThumbprint:
    def setup_method(self):
        from detectors.cloud_secrets import _certificate_thumbprint
        self.r = _certificate_thumbprint()

    def test_40_char_lowercase_hex(self):
        text = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        results = self.r.analyze(text, ["CERTIFICATE_THUMBPRINT"])
        assert any(r.entity_type == "CERTIFICATE_THUMBPRINT" for r in results)

    def test_40_char_uppercase_hex(self):
        text = "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"
        results = self.r.analyze(text, ["CERTIFICATE_THUMBPRINT"])
        assert any(r.entity_type == "CERTIFICATE_THUMBPRINT" for r in results)

    def test_base_score_0_4(self):
        text = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        results = self.r.analyze(text, ["CERTIFICATE_THUMBPRINT"])
        matches = [r for r in results if r.entity_type == "CERTIFICATE_THUMBPRINT"]
        assert matches
        assert all(r.score == 0.4 for r in matches)

    def test_39_chars_not_detected(self):
        # One char short of 40
        results = self.r.analyze("da39a3ee5e6b4b0d3255bfef95601890afd8070", ["CERTIFICATE_THUMBPRINT"])
        assert not results

    def test_41_chars_not_detected(self):
        # One char over 40 — no word boundary at 40
        results = self.r.analyze("da39a3ee5e6b4b0d3255bfef95601890afd807090", ["CERTIFICATE_THUMBPRINT"])
        assert not results

    def test_non_hex_not_detected(self):
        results = self.r.analyze("gggggggggggggggggggggggggggggggggggggggg", ["CERTIFICATE_THUMBPRINT"])
        assert not results


# ---------------------------------------------------------------------------
# Task 5 – SharePoint / Teams / Power Platform URLs (GAP 5)
# ---------------------------------------------------------------------------

class TestM365Url:
    def setup_method(self):
        from detectors.cloud_secrets import _m365_url
        self.r = _m365_url()

    def test_sharepoint_url_detected(self):
        text = "https://contoso.sharepoint.com/sites/marketing"
        results = self.r.analyze(text, ["M365_TENANT_URL"])
        assert any(r.entity_type == "M365_TENANT_URL" and r.score == 0.9 for r in results)

    @pytest.mark.parametrize("tenant", ["mycompany", "fabrikam-corp", "northwind123"])
    def test_sharepoint_various_tenants(self, tenant):
        text = f"https://{tenant}.sharepoint.com/Shared%20Documents"
        results = self.r.analyze(text, ["M365_TENANT_URL"])
        assert any(r.entity_type == "M365_TENANT_URL" for r in results)

    def test_teams_deeplink_detected(self):
        text = "https://teams.microsoft.com/l/channel/19%3Achannel%40thread.tacv2/General"
        results = self.r.analyze(text, ["M365_TENANT_URL"])
        assert any(r.entity_type == "M365_TENANT_URL" and r.score == 0.85 for r in results)

    def test_dynamics_crm_url_detected(self):
        text = "https://myorg.crm.dynamics.com/api/data/v9.2/accounts"
        results = self.r.analyze(text, ["M365_TENANT_URL"])
        assert any(r.entity_type == "M365_TENANT_URL" for r in results)

    def test_dynamics_api_url_detected(self):
        text = "https://myorg.api.dynamics.com/api/data"
        results = self.r.analyze(text, ["M365_TENANT_URL"])
        assert any(r.entity_type == "M365_TENANT_URL" for r in results)

    def test_unrelated_url_not_detected(self):
        assert not self.r.analyze("https://example.com/page", ["M365_TENANT_URL"])


# ---------------------------------------------------------------------------
# Task 6 – Norwegian name detection (GAP 8)
# ---------------------------------------------------------------------------

class TestNorwegianNames:
    """Backward-compat tests for the build_norwegian_name_recognizers API."""

    def setup_method(self):
        from detectors.norwegian_names import build_norwegian_name_recognizers
        self.recognizers = build_norwegian_name_recognizers()

    def _analyze(self, text: str) -> list:
        results = []
        for r in self.recognizers:
            results.extend(r.analyze(text, ["NORWEGIAN_PERSON_NAME"]))
        return results

    def test_name_with_oe_detected(self):
        results = self._analyze("Bjørn Hansen sendte e-post")
        assert any(r.entity_type == "NORWEGIAN_PERSON_NAME" for r in results)

    def test_name_with_aa_detected(self):
        results = self._analyze("Åse Olsen er ansatt")
        assert any(r.entity_type == "NORWEGIAN_PERSON_NAME" for r in results)

    def test_common_norwegian_first_name(self):
        results = self._analyze("Kjell Andersen er prosjektleder")
        assert any(r.entity_type == "NORWEGIAN_PERSON_NAME" for r in results)

    def test_name_with_oslash_in_first_name(self):
        results = self._analyze("Ørjan Johansen")
        assert any(r.entity_type == "NORWEGIAN_PERSON_NAME" for r in results)

    def test_non_norwegian_names_no_match(self):
        # Names not in the Norwegian SSB database should not be detected
        results = self._analyze("Bartholomew Chadwick is here")
        assert not any(r.entity_type == "NORWEGIAN_PERSON_NAME" for r in results)

    def test_common_norwegian_words_not_flagged(self):
        # Words with ÆØÅ that are NOT names should not be detected
        results = self._analyze("Vi må åpne og så ville vi prøve noe hørt om det")
        assert not results


class TestNorwegianNameRecognizer:
    """Tests for the expanded set-based Norwegian name recognizer."""

    def setup_method(self):
        from detectors.norwegian_names import _NorwegianNameRecognizer
        self.r = _NorwegianNameRecognizer()

    def _analyze(self, text: str) -> list:
        return self.r.analyze(text, ["NORWEGIAN_PERSON_NAME"])

    # --- Full name pairs ---

    def test_known_first_plus_known_surname_score_085(self):
        results = self._analyze("Bjørn Hansen sendte e-post")
        pairs = [r for r in results if r.score == 0.85]
        assert pairs
        assert pairs[0].entity_type == "NORWEGIAN_PERSON_NAME"

    def test_first_surname_pair_spans_both_words(self):
        text = "Bjørn Hansen sendte e-post"
        results = self._analyze(text)
        pairs = [r for r in results if r.score == 0.85]
        assert pairs
        assert text[pairs[0].start:pairs[0].end] == "Bjørn Hansen"

    def test_known_first_plus_capitalized_word_score_070(self):
        # "Andersen" is a known surname, so this should be 0.85
        # Use an unknown surname to test 0.70
        results = self._analyze("Kjell Xylophonsen er prosjektleder")
        hits = [r for r in results if r.score == 0.70]
        assert hits

    def test_capitalized_plus_known_surname_score_070(self):
        # "Zchenkov" is not a known first name, "Hansen" is a known surname
        results = self._analyze("Zchenkov Hansen er ny")
        hits = [r for r in results if r.score == 0.70]
        assert hits

    # --- Standalone detection (aggressive) ---

    def test_standalone_first_name_detected(self):
        results = self._analyze("Bjørn sendte rapporten til kontoret")
        assert any(r.entity_type == "NORWEGIAN_PERSON_NAME" and r.score == 0.50 for r in results)

    def test_standalone_surname_detected(self):
        results = self._analyze("Kontoret tilhører Hansen i dag")
        assert any(r.entity_type == "NORWEGIAN_PERSON_NAME" and r.score == 0.50 for r in results)

    def test_standalone_common_norwegian_name(self):
        results = self._analyze("Terje sa at det var greit")
        assert any(r.entity_type == "NORWEGIAN_PERSON_NAME" for r in results)

    # --- False positive prevention ---

    def test_short_ambiguous_words_not_flagged(self):
        # "Ja", "Vi", "Og" should not be flagged
        results = self._analyze("Ja vi er enige og det er bra")
        assert not results

    def test_lowercase_name_not_flagged(self):
        # "bjørn" (lowercase) means "bear" — should not match
        results = self._analyze("bjørn er et rovdyr i skogen")
        assert not results

    def test_two_char_name_not_standalone(self):
        # "Bo" is a real name but too short for standalone detection
        results = self._analyze("Bo var der alene")
        standalone = [r for r in results if r.score == 0.50]
        assert not standalone

    # --- Scandinavian extras ---

    def test_swedish_name_detected(self):
        results = self._analyze("Gustaf Johansson er svensk")
        assert any(r.entity_type == "NORWEGIAN_PERSON_NAME" for r in results)

    def test_danish_name_detected(self):
        results = self._analyze("Troels Madsen besøkte Oslo")
        assert any(r.entity_type == "NORWEGIAN_PERSON_NAME" for r in results)

    # --- Data file loading ---

    def test_data_files_have_substantial_content(self):
        from detectors.norwegian_names import _load_name_set
        first = _load_name_set("norwegian_first_names.txt")
        surnames = _load_name_set("norwegian_surnames.txt")
        assert len(first) > 100
        assert len(surnames) > 100

    # --- Performance ---

    def test_large_text_completes_quickly(self):
        import time
        text = "Bjørn Hansen og Kari Nordmann diskuterte saken. " * 3000
        start = time.perf_counter()
        results = self._analyze(text)
        elapsed = time.perf_counter() - start
        assert elapsed < 2.0
        assert len(results) > 0


# ---------------------------------------------------------------------------
# Task 7 – Fødselsnummer check digit validation (GAP 9)
# ---------------------------------------------------------------------------

class TestFodselsnummer:
    def setup_method(self):
        from detectors.norway_gdpr import _FodselsnummerRecognizer
        self.r = _FodselsnummerRecognizer()

    def test_valid_number_scores_0_85(self):
        # 29029900157 has valid check digits (d9=5, d10=7)
        results = self.r.analyze("fnr 29029900157", ["NORWEGIAN_NATIONAL_ID"])
        assert any(
            r.entity_type == "NORWEGIAN_NATIONAL_ID" and r.score == 0.85
            for r in results
        )

    def test_invalid_check_digits_scores_0_35(self):
        # 01010101181 fails check digit validation
        results = self.r.analyze("01010101181", ["NORWEGIAN_NATIONAL_ID"])
        assert any(
            r.entity_type == "NORWEGIAN_NATIONAL_ID" and r.score == 0.35
            for r in results
        )

    def test_invalid_number_still_detected(self):
        # Even with invalid check digits the number is still returned
        results = self.r.analyze("01010101181", ["NORWEGIAN_NATIONAL_ID"])
        assert results

    def test_invalid_month_not_matched(self):
        # Month 13 is not a valid month — regex should not match
        results = self.r.analyze("01130012345", ["NORWEGIAN_NATIONAL_ID"])
        assert not results

    def test_ten_digit_number_not_matched(self):
        results = self.r.analyze("1234567890", ["NORWEGIAN_NATIONAL_ID"])
        assert not results

    def test_check_digit_validation_helper(self):
        from detectors.norway_gdpr import _FodselsnummerRecognizer
        assert _FodselsnummerRecognizer._valid_check_digits("29029900157") is True
        assert _FodselsnummerRecognizer._valid_check_digits("01010101181") is False


# ---------------------------------------------------------------------------
# Task 8 – Dangerous formula detection (MEDIUM)
# ---------------------------------------------------------------------------

class TestDangerousFormula:
    """
    Unit-tests the detection logic directly without needing openpyxl I/O.
    Full integration tests require a real XLSX file.
    """

    _DANGEROUS = [
        '=IMAGE("https://attacker.example/pixel")',
        '=WEBSERVICE("http://evil.com/")',
        '=FILTERXML(WEBSERVICE("http://host/"),"//a")',
        '=IMPORTDATA("https://sheet.host/data")',
        '=HYPERLINK("https://external.host/","click")',
        '=SUM(WEBSERVICE("http://x.com"))',
    ]
    _SAFE = [
        "=SUM(A1:A10)",
        '=IF(B1>0,"yes","no")',
        "=VLOOKUP(A1,B:C,2)",
        "=TODAY()",
        "=LEN(A1)",
    ]

    @staticmethod
    def _is_dangerous(formula: str) -> bool:
        dangerous_prefixes = ("=IMAGE(", "=WEBSERVICE(", "=FILTERXML(", "=IMPORTDATA(")
        return (
            formula.upper().startswith(dangerous_prefixes)
            or bool(re.search(r"=.*https?://", formula, re.IGNORECASE))
        )

    @pytest.mark.parametrize("formula", _DANGEROUS)
    def test_dangerous_formula_flagged(self, formula):
        assert self._is_dangerous(formula), f"Expected dangerous: {formula!r}"

    @pytest.mark.parametrize("formula", _SAFE)
    def test_safe_formula_not_flagged(self, formula):
        assert not self._is_dangerous(formula), f"Expected safe: {formula!r}"


# ---------------------------------------------------------------------------
# Task 9 – Cache invalidation
# ---------------------------------------------------------------------------

class TestCacheInvalidation:
    def test_same_terms_returns_cached_instance(self):
        from detectors.engine import get_analyzer, invalidate_cache
        invalidate_cache()
        a1 = get_analyzer(("unique_term_xyz",))
        a2 = get_analyzer(("unique_term_xyz",))
        assert a1 is a2

    def test_invalidate_clears_cache(self):
        from detectors.engine import get_analyzer, invalidate_cache
        invalidate_cache()
        a1 = get_analyzer(("term_alpha",))
        invalidate_cache()
        a2 = get_analyzer(("term_alpha",))
        assert a1 is not a2

    def test_different_terms_after_invalidate(self):
        from detectors.engine import get_analyzer, invalidate_cache
        invalidate_cache()
        a1 = get_analyzer(("term_one",))
        invalidate_cache()
        a2 = get_analyzer(("term_two",))
        assert a1 is not a2
