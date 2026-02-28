from __future__ import annotations
import json
import os
import stat
import base64
from pathlib import Path
from dataclasses import dataclass, field
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet, InvalidToken


PBKDF2_ITERATIONS = 600_000
PBKDF2_ITERATIONS_LEGACY = 100_000


def _derive_key(password: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


@dataclass
class SanitizeSession:
    """
    Tracks the token<->original_value mapping for a single sanitize run.
    Token format: [ENTITY_TYPE_N] e.g. [PERSON_1], [AWS_KEY_3]
    """
    _counters: dict[str, int] = field(default_factory=dict, init=False, repr=False)
    _value_to_token: dict[str, str] = field(default_factory=dict, init=False, repr=False)
    _token_to_value: dict[str, str] = field(default_factory=dict, init=False, repr=False)

    def get_or_create_token(self, detection) -> str:
        """Return existing token for this value, or create a new deterministic one."""
        value = detection.original_value
        if value in self._value_to_token:
            return self._value_to_token[value]
        entity = detection.entity_type
        n = self._counters.get(entity, 0) + 1
        self._counters[entity] = n
        token = f"[{entity}_{n}]"
        self._value_to_token[value] = token
        self._token_to_value[token] = value
        return token

    @property
    def token_map(self) -> dict[str, str]:
        return dict(self._token_to_value)

    def save_vault(self, vault_path: Path, password: str) -> None:
        """Encrypt and save the token map to a .vault file."""
        salt = os.urandom(16)
        key = _derive_key(password, salt, PBKDF2_ITERATIONS)
        f = Fernet(key)
        payload = json.dumps(self._token_to_value).encode("utf-8")
        encrypted = f.encrypt(payload)
        vault_data = {
            "version": 1,
            "kdf_iterations": PBKDF2_ITERATIONS,
            "salt": base64.b64encode(salt).decode("ascii"),
            "data": encrypted.decode("ascii"),  # Fernet token is already base64url
        }
        vault_path.write_text(json.dumps(vault_data, indent=2), encoding="utf-8")
        try:
            vault_path.chmod(stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass  # best-effort; Windows ACLs don't map to Unix permissions
        self._counters.clear()
        self._value_to_token.clear()
        self._token_to_value.clear()

    @staticmethod
    def load_vault(vault_path: Path, password: str) -> dict[str, str]:
        """Decrypt and return the token map from a .vault file."""
        try:
            raw = json.loads(vault_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            raise ValueError(f"Cannot read vault file: {e}") from e

        if not isinstance(raw, dict) or "salt" not in raw or "data" not in raw:
            raise ValueError(
                "Invalid vault file: missing required fields ('salt', 'data')."
            )

        version = raw.get("version", 0)
        iterations = raw.get("kdf_iterations", PBKDF2_ITERATIONS_LEGACY)

        try:
            salt = base64.b64decode(raw["salt"])
        except Exception as e:
            raise ValueError(f"Invalid vault file: corrupted salt field.") from e

        key = _derive_key(password, salt, iterations)
        f = Fernet(key)

        try:
            if version >= 1:
                # v1+: data is stored as the Fernet token directly (base64url string)
                encrypted = raw["data"].encode("ascii")
            else:
                # v0 (legacy): data was double base64-encoded
                encrypted = base64.b64decode(raw["data"])
            payload = f.decrypt(encrypted)
        except InvalidToken:
            raise ValueError(
                "Wrong password or corrupted vault. "
                "Please check the password and try again."
            )
        except Exception as e:
            raise ValueError(f"Failed to decrypt vault: {e}") from e

        try:
            return json.loads(payload.decode("utf-8"))
        except json.JSONDecodeError as e:
            raise ValueError(f"Vault data is corrupted: {e}") from e
