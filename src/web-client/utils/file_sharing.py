import base64
import json
import os
import nacl.public
import nacl.signing
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from utils.auth.session_manager import LoginSessionManager
from constants import KEYS_PATH, BINARY_EXTENSION
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

def generate_one_time_pre_key_pairs(username: str, count: int = 50) -> list:
    """Generates multiple one-time pre-key pairs for secure communication."""
    logger.info(f"Generating {count} one-time pre-key pairs.")
    
    private_keys = [nacl.public.PrivateKey.generate() for _ in range(count)]
    public_keys = [base64.b64encode(pk.public_key.encode()).decode() for pk in private_keys]
    private_keys = [base64.b64encode(pk.encode()).decode() for pk in private_keys]

    if _save_key_pairs_locally(username, "one_time_pre_keys", public_keys, private_keys):
        logger.info("One-time pre-key pairs saved locally.")
    else:
        logger.error("Failed to save one-time pre-key pairs locally.")
    return public_keys

def generate_signed_pre_key(identity_private_key_base64: str) -> tuple:
    """Generates a signed pre-key using the identity key pair."""
    identity_private_key = nacl.signing.SigningKey(base64.b64decode(identity_private_key_base64))
    signed_pre_key = nacl.public.PrivateKey.generate()
    signature = identity_private_key.sign(signed_pre_key.public_key.encode()).signature

    return (
        base64.b64encode(signed_pre_key.public_key.encode()).decode(),
        base64.b64encode(signed_pre_key.encode()).decode(),
        base64.b64encode(signature).decode()
    )

def verify_signed_pre_key(identity_public_key_base64: str, signed_pre_key_public_base64: str, signature_base64: str) -> bool:
    """Verifies the signed pre-key using the identity public key."""
    identity_public_key = nacl.signing.VerifyKey(base64.b64decode(identity_public_key_base64))
    
    try:
        identity_public_key.verify(base64.b64decode(signed_pre_key_public_base64), base64.b64decode(signature_base64))
        return True
    except nacl.exceptions.BadSignatureError:
        logger.warning("Signed pre-key verification failed: Bad signature.")
        return False

def _save_key_pairs_locally(username: str, key_type: str, public_keys: list, private_keys: list) -> bool:
    """Generic key storage method for different key types."""
    file_path = Path(KEYS_PATH + username).with_suffix(BINARY_EXTENSION)
    master_key = LoginSessionManager.getInstance().getMasterKey()
    if not master_key:
        logger.info("Master key not found. Cannot save key pairs.")
        raise ValueError("Master key not found. Cannot save key pairs.")
    LoginSessionManager.getInstance().setMasterKey(master_key)
    
    if not master_key:
        logger.error("Master key not found. Cannot save key pairs.")
        return False

    try:
        encrypted_data = _encrypt_data(json.dumps({key_type: {"public_keys": public_keys, "private_keys": private_keys}}).encode(), master_key)
        file_path.write_bytes(encrypted_data)
        logger.info(f"Key pairs saved to {file_path}.")
        return True
    except Exception as e:
        logger.exception(f"Failed to save key pairs: {e}")
        return False


def read_and_decrypt_key_storage(filepath: str, master_key: bytes) -> dict:
    """Reads and decrypts the key storage file."""
    if not Path(filepath).exists():
        logger.warning(f"Key storage file {filepath} does not exist.")
        return {}

    try:
        encrypted_data = Path(filepath).read_bytes()
        return json.loads(_decrypt_data(encrypted_data, master_key).decode())
    except Exception as e:
        logger.exception(f"Failed to read or decrypt key storage: {e}")
        return {}

def _encrypt_data(data: bytes, key: bytes) -> bytes:
    """Encrypts data using ChaCha20-Poly1305."""
    cipher = ChaCha20Poly1305(key)
    nonce = os.urandom(12)
    return nonce + cipher.encrypt(nonce, data, None)

def _decrypt_data(encrypted_data: bytes, key: bytes) -> bytes:
    """Decrypts data using ChaCha20-Poly1305."""
    cipher = ChaCha20Poly1305(key)
    return cipher.decrypt(encrypted_data[:12], encrypted_data[12:], None)