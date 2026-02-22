from presidio_analyzer import PatternRecognizer, Pattern


def build_cloud_recognizers() -> list[PatternRecognizer]:
    return [
        _aws_access_key(),
        _aws_arn(),
        _aws_account_id(),
        _azure_connection_string(),
        _azure_client_secret(),
        _azure_uuid(),
        _azure_sas_token(),
        _jwt_token(),
        _certificate_thumbprint(),
        _m365_url(),
        _azure_resource_id(),
        _azure_tenant_domain(),
        _azure_resource_name(),
        _gcp_service_account(),
        _gcp_api_key(),
        _generic_secret(),
        _internal_hostname(),
        _private_ip(),
        _norwegian_company(),
        _norwegian_org_number(),
        _file_path(),
    ]


def _aws_access_key() -> PatternRecognizer:
    return PatternRecognizer(
        supported_entity="AWS_ACCESS_KEY",
        patterns=[Pattern(name="aws_access_key", regex=r"AKIA[0-9A-Z]{16}", score=0.9)],
        context=["aws", "key", "access"],
    )


def _aws_arn() -> PatternRecognizer:
    return PatternRecognizer(
        supported_entity="AWS_ARN",
        patterns=[Pattern(
            name="aws_arn",
            regex=r"arn:aws:[a-z0-9\-]+:[a-z0-9\-]*:[0-9]{0,12}:[a-zA-Z0-9\-_/:.]+",
            score=0.85,
        )],
    )


def _aws_account_id() -> PatternRecognizer:
    return PatternRecognizer(
        supported_entity="AWS_ACCOUNT_ID",
        patterns=[Pattern(name="aws_account_id", regex=r"\b\d{12}\b", score=0.4)],
        context=["account", "aws", "billing", "organization"],
    )


def _azure_connection_string() -> PatternRecognizer:
    return PatternRecognizer(
        supported_entity="AZURE_CONNECTION_STRING",
        patterns=[Pattern(
            name="azure_conn_str",
            regex=r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]+;[^\s\"']*",
            score=0.95,
        )],
    )


def _azure_client_secret() -> PatternRecognizer:
    return PatternRecognizer(
        supported_entity="AZURE_CLIENT_SECRET",
        patterns=[Pattern(
            name="azure_client_secret",
            regex=r"(?i)client[-_]?secret\s*[:=]\s*[A-Za-z0-9_~\-\.]{20,}",
            score=0.8,
        )],
    )


def _azure_uuid() -> PatternRecognizer:
    return PatternRecognizer(
        supported_entity="AZURE_UUID",
        patterns=[
            Pattern(
                name="azure_uuid",
                regex=r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
                score=0.6,
            ),
            Pattern(
                name="azure_uuid_json_value",
                regex=r'(?<=": ")[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
                score=0.8,
            ),
        ],
        context=["id", "guid", "objectid", "appid", "serviceprincipal", "directory", "entra", "aad", "registration", "application", "principal", "resourcegroup", "resource", "subscription", "tenant", "client_id", "object_id", "azure"],
    )


def _azure_sas_token() -> PatternRecognizer:
    """Azure Shared Access Signature tokens in URLs expose storage access credentials."""
    return PatternRecognizer(
        supported_entity="AZURE_SAS_TOKEN",
        patterns=[Pattern(
            name="azure_sas_token",
            regex=r"[?&](?:sv|sig)=[^&\s]{10,}(?:&[a-z]{1,4}=[^&\s]*){2,}",
            score=0.9,
        )],
    )


def _jwt_token() -> PatternRecognizer:
    """JWT tokens and Bearer headers expose authentication credentials."""
    return PatternRecognizer(
        supported_entity="JWT_BEARER_TOKEN",
        patterns=[
            Pattern(
                name="jwt_compact",
                regex=r"eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}",
                score=0.95,
            ),
            Pattern(
                name="bearer_header",
                regex=r"(?i)Bearer\s+[A-Za-z0-9_\-.~+/]+=*",
                score=0.85,
            ),
        ],
    )


def _certificate_thumbprint() -> PatternRecognizer:
    """Certificate thumbprints (SHA-1 fingerprints) identify certificates and keys."""
    return PatternRecognizer(
        supported_entity="CERTIFICATE_THUMBPRINT",
        patterns=[Pattern(
            name="cert_thumbprint",
            regex=r"\b[0-9A-Fa-f]{40}\b",
            score=0.4,
        )],
        context=["thumbprint", "certificate", "cert", "sha1", "fingerprint", "keyid", "x509", "sertifikat"],
    )


def _m365_url() -> PatternRecognizer:
    """Microsoft 365 tenant-identifying URLs reveal organisation identity and structure."""
    return PatternRecognizer(
        supported_entity="M365_TENANT_URL",
        patterns=[
            Pattern(
                name="sharepoint_url",
                regex=r"https?://[a-zA-Z0-9-]+\.sharepoint\.com[^\s\"']*",
                score=0.9,
            ),
            Pattern(
                name="teams_deeplink",
                regex=r"https?://teams\.microsoft\.com/l/[^\s\"']*",
                score=0.85,
            ),
            Pattern(
                name="power_platform_url",
                regex=r"https?://[a-zA-Z0-9-]+\.(?:crm|api)\.dynamics\.com[^\s\"']*",
                score=0.85,
            ),
        ],
    )


def _azure_resource_id() -> PatternRecognizer:
    # Full Azure resource ID: /subscriptions/{guid}/resourceGroups/{name}/providers/...
    return PatternRecognizer(
        supported_entity="AZURE_RESOURCE_ID",
        patterns=[Pattern(
            name="azure_resource_id",
            regex=r"/subscriptions/[0-9a-f\-]{36}(?:/resourceGroups/[^/\s\"']+)?(?:/providers/[^/\s\"']+(?:/[^/\s\"']+)*)?",
            score=0.9,
        )],
    )


def _azure_tenant_domain() -> PatternRecognizer:
    # onmicrosoft.com tenant domains and known AAD-linked custom domains in context
    return PatternRecognizer(
        supported_entity="AZURE_TENANT_DOMAIN",
        patterns=[
            Pattern(
                name="onmicrosoft_domain",
                regex=r"\b[A-Za-z0-9-]+\.onmicrosoft\.com\b",
                score=0.95,
            ),
        ],
        context=["tenant", "domain", "upn", "azure", "entra", "aad", "directory"],
    )


def _azure_resource_name() -> PatternRecognizer:
    # Display names and identifiers found in Entra/Azure reports:
    # TenantDisplayName, TenantId keys, AppDisplayName, ServicePrincipalName etc.
    return PatternRecognizer(
        supported_entity="AZURE_RESOURCE_NAME",
        patterns=[
            Pattern(
                name="tenant_display_name",
                regex=r'(?i)(?:TenantDisplayName|TenantName|OrganizationName|DisplayName|AppDisplayName|ServicePrincipalName)\s{0,3}[":]?\s{0,3}([A-Za-z0-9][A-Za-z0-9 \-_\.]{1,63})',
                score=0.75,
            ),
            Pattern(
                name="resource_group",
                regex=r'(?i)resourceGroup(?:s|Name)?(?:\s*[":/]\s*|\s+)([A-Za-z0-9\-_\.]{2,90})',
                score=0.70,
            ),
        ],
    )


def _gcp_service_account() -> PatternRecognizer:
    return PatternRecognizer(
        supported_entity="GCP_SERVICE_ACCOUNT",
        patterns=[Pattern(
            name="gcp_sa",
            regex=r'"type"\s*:\s*"service_account"',
            score=0.95,
        )],
    )


def _gcp_api_key() -> PatternRecognizer:
    return PatternRecognizer(
        supported_entity="GCP_API_KEY",
        patterns=[Pattern(
            name="gcp_api_key",
            regex=r"AIza[0-9A-Za-z_\-]{35}",
            score=0.9,
        )],
    )


def _generic_secret() -> PatternRecognizer:
    patterns = [
        Pattern(
            name="password_assign",
            regex=r"(?i)password\s*[:=]\s*\S+",
            score=0.75,
        ),
        Pattern(
            name="token_assign",
            regex=r"(?i)token\s*[:=]\s*\S+",
            score=0.7,
        ),
        Pattern(
            name="api_key_assign",
            regex=r"(?i)api[-_]?key\s*[:=]\s*\S+",
            score=0.75,
        ),
        Pattern(
            name="secret_assign",
            regex=r"(?i)secret\s*[:=]\s*\S+",
            score=0.7,
        ),
    ]
    return PatternRecognizer(supported_entity="GENERIC_SECRET", patterns=patterns)


def _internal_hostname() -> PatternRecognizer:
    return PatternRecognizer(
        supported_entity="INTERNAL_HOSTNAME",
        patterns=[Pattern(
            name="hostname",
            regex=r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:local|internal|corp|intranet|lan|home|localdomain)\b",
            score=0.7,
        )],
    )


def _norwegian_company() -> PatternRecognizer:
    # Matches company names ending with a Norwegian legal form suffix.
    # Covers: AS, ASA, ANS, DA, ENK, NUF, SA, BA, KS, IKS, SF, SE, STI, FKF, KF
    # Examples: "Sicra AS", "Equinor ASA", "Norsk Hydro AS", "NRK SF"
    return PatternRecognizer(
        supported_entity="NORWEGIAN_COMPANY",
        patterns=[Pattern(
            name="norwegian_company",
            regex=(
                r"\b[A-ZÆØÅ][a-zA-ZæøåÆØÅ0-9]"
                r"(?:[a-zA-ZæøåÆØÅ0-9\s&\-\.]{0,60}?\s)?"
                r"(?:ASA|ANS|IKS|NUF|FKF|ENK|AS|DA|SA|BA|KS|SF|SE|STI|KF)\b"
            ),
            score=0.75,
        )],
    )


def _norwegian_org_number() -> PatternRecognizer:
    # Norwegian organisation numbers: 9 digits, optionally space-separated as NNN NNN NNN
    # Often followed by "MVA" for VAT-registered entities
    return PatternRecognizer(
        supported_entity="NORWEGIAN_ORG_NUMBER",
        patterns=[
            Pattern(
                name="org_no_spaced",
                regex=r"\b\d{3}[ ]?\d{3}[ ]?\d{3}(?:\s+MVA)?\b",
                score=0.6,
            ),
        ],
        context=["org", "orgnr", "organisasjonsnummer", "organisasjon", "mva", "foretaksnummer"],
    )


def _file_path() -> PatternRecognizer:
    return PatternRecognizer(
        supported_entity="FILE_PATH",
        patterns=[
            # Windows absolute path: C:\foo\bar or C:\\foo\\bar (at least one subdirectory)
            Pattern(
                name="windows_path",
                regex=r"[A-Za-z]:\\{1,2}(?:[^\\/:*?\"<>|\r\n]+\\{1,2})+[^\\/:*?\"<>|\r\n]*",
                score=0.75,
            ),
            # UNC path: \\server\share\...
            Pattern(
                name="unc_path",
                regex=r"\\\\[A-Za-z0-9._-]+\\[A-Za-z0-9._-]+(?:\\[^\\/:*?\"<>|\r\n]*)*",
                score=0.75,
            ),
            # Unix absolute path with at least two components: /foo/bar
            Pattern(
                name="unix_path",
                regex=r"(?<![:\w])/(?:[A-Za-z0-9._~-]+/)+[A-Za-z0-9._~-]*",
                score=0.6,
            ),
        ],
    )


def _private_ip() -> PatternRecognizer:
    return PatternRecognizer(
        supported_entity="PRIVATE_IP",
        patterns=[Pattern(
            name="rfc1918",
            regex=r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b",
            score=0.8,
        )],
    )
