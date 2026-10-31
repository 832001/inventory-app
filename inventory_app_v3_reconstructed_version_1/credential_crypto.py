"""
Symmetric encryption for hypervisor connection credentials.

Uses Fernet (AES-128-CBC + HMAC-SHA256 + random IV). Encrypted values
are strings — safe to store in the JSON `connection_options` column.

The master key comes from the CREDENTIAL_MASTER_KEY env var (via
config.CREDENTIAL_MASTER_KEY). Rotating the key requires re-encrypting
every stored password — see rotate_key.py (not included by default).
"""
import logging
from cryptography.fernet import Fernet, InvalidToken

from config import CREDENTIAL_MASTER_KEY

logger = logging.getLogger("inventory_app.crypto")

_fernet = None


def _get_fernet():
    global _fernet
    if _fernet is None:
        if not CREDENTIAL_MASTER_KEY:
            raise RuntimeError(
                "CREDENTIAL_MASTER_KEY is not set. Generate one with:\n"
                "  python3 -c \"from cryptography.fernet import Fernet; "
                "print(Fernet.generate_key().decode())\"\n"
                "then put it in .env as CREDENTIAL_MASTER_KEY=...")
        try:
            _fernet = Fernet(CREDENTIAL_MASTER_KEY.encode()
                             if isinstance(CREDENTIAL_MASTER_KEY, str)
                             else CREDENTIAL_MASTER_KEY)
        except Exception as e:
            raise RuntimeError(f"Invalid CREDENTIAL_MASTER_KEY: {e}") from e
    return _fernet


def encrypt(plaintext: str) -> str:
    """Return the encrypted form as a base64 string."""
    if plaintext is None or plaintext == "":
        return ""
    return _get_fernet().encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt(ciphertext: str) -> str:
    """Return the plaintext. Raises ValueError on tampered/invalid input."""
    if not ciphertext:
        return ""
    try:
        return _get_fernet().decrypt(ciphertext.encode("ascii")).decode("utf-8")
    except InvalidToken as e:
        raise ValueError(
            "Cannot decrypt credential — the value is corrupted, "
            "or the MASTER_KEY has changed since it was encrypted.") from e


def is_encrypted(value: str) -> bool:
    """True if the value looks like a Fernet token (starts with 'gAAAAA')."""
    return isinstance(value, str) and value.startswith("gAAAAA")


def encrypt_options(opts: dict) -> dict:
    """Return a copy of an options dict with password/token_secret encrypted."""
    out = dict(opts or {})
    for key in ("password", "token_secret"):
        v = out.get(key)
        if v and not is_encrypted(v):
            out[key] = encrypt(v)
    return out


def decrypt_options(opts: dict) -> dict:
    """Return a copy of an options dict with password/token_secret decrypted.
    Silently leaves already-plaintext values alone (backward compatible)."""
    out = dict(opts or {})
    for key in ("password", "token_secret"):
        v = out.get(key)
        if not v:
            continue
        if is_encrypted(v):
            try:
                out[key] = decrypt(v)
            except ValueError:
                logger.exception("Failed to decrypt %s", key)
                out[key] = ""      # fail safe — treat as empty
    return out
