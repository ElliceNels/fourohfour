from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
    crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
    crypto_aead_xchacha20poly1305_ietf_ABYTES,
    crypto_aead_xchacha20poly1305_ietf_encrypt,
    crypto_aead_xchacha20poly1305_ietf_decrypt
)
import nacl.utils

class EncryptionHelper:
    def __init__(self):
        pass

    @staticmethod
    def generate_key():
        """" 
        Returns a securely generated random key
        """
        return nacl.utils.random(crypto_aead_xchacha20poly1305_ietf_KEYBYTES)

    @staticmethod
    def generate_nonce():
        # Returns a securely generated random nonce
        return nacl.utils.random(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)

    @staticmethod
    def encrypt(plaintext: bytes, key: bytes, nonce: bytes, additional_data: bytes = None) -> bytes:
        if len(key) != crypto_aead_xchacha20poly1305_ietf_KEYBYTES:
            raise ValueError(f"Key must be {crypto_aead_xchacha20poly1305_ietf_KEYBYTES} bytes")
        if len(nonce) != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES:
            raise ValueError(f"Nonce must be {crypto_aead_xchacha20poly1305_ietf_NPUBBYTES} bytes")
        if additional_data is None:
            additional_data = b''
        ciphertext = crypto_aead_xchacha20poly1305_ietf_encrypt(
            plaintext,
            additional_data,
            nonce,
            key
        )
        return ciphertext

    @staticmethod
    def decrypt(ciphertext: bytes, key: bytes, nonce: bytes, additional_data: bytes = None) -> bytes:
        if len(key) != crypto_aead_xchacha20poly1305_ietf_KEYBYTES:
            raise ValueError(f"Key must be {crypto_aead_xchacha20poly1305_ietf_KEYBYTES} bytes")
        if len(nonce) != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES:
            raise ValueError(f"Nonce must be {crypto_aead_xchacha20poly1305_ietf_NPUBBYTES} bytes")
        if len(ciphertext) < crypto_aead_xchacha20poly1305_ietf_ABYTES:
            raise ValueError("Ciphertext too short")
        if additional_data is None:
            additional_data = b''
        try:
            plaintext = crypto_aead_xchacha20poly1305_ietf_decrypt(
                ciphertext,
                additional_data,
                nonce,
                key
            )
        except Exception as e:
            raise RuntimeError("Decryption failed or message forged") from e
        return plaintext
    