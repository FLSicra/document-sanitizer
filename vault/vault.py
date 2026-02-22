from __future__ import annotations
import json
import os
import base64
from pathlib import Path
from dataclasses import dataclass, field
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet


PBKDF2_ITERATIONS = 100_000


def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
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
        key = _derive_key(password, salt)
        f = Fernet(key)
        payload = json.dumps(self._token_to_value).encode("utf-8")
        encrypted = f.encrypt(payload)
        vault_data = {
            "salt": base64.b64encode(salt).decode("ascii"),
            "data": base64.b64encode(encrypted).decode("ascii"),
        }
        vault_path.write_text(json.dumps(vault_data, indent=2), encoding="utf-8")

    @staticmethod
    def load_vault(vault_path: Path, password: str) -> dict[str, str]:
        """Decrypt and return the token map from a .vault file."""
        raw = json.loads(vault_path.read_text(encoding="utf-8"))
        salt = base64.b64decode(raw["salt"])
        encrypted = base64.b64decode(raw["data"])
        key = _derive_key(password, salt)
        f = Fernet(key)
        payload = f.decrypt(encrypted)
        return json.loads(payload.decode("utf-8"))
