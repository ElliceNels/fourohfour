from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
    crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
    crypto_aead_xchacha20poly1305_ietf_ABYTES,
    crypto_aead_xchacha20poly1305_ietf_encrypt,
    crypto_aead_xchacha20poly1305_ietf_decrypt
)
import nacl.utils

class EncryptionHelper:
    """
    Helper class for XChaCha20-Poly1305 encryption and decryption using PyNaCl.
    Provides static methods for key/nonce generation, encryption, and decryption.
    """

    def __init__(self):
        pass

    @staticmethod
    def generate_key() -> bytes:
        """
        Generate a securely random key for XChaCha20-Poly1305.

        Returns:
            bytes: A random key of length crypto_aead_xchacha20poly1305_ietf_KEYBYTES.
        """
        return nacl.utils.random(crypto_aead_xchacha20poly1305_ietf_KEYBYTES)

    @staticmethod
    def generate_nonce() -> bytes:
        """
        Generate a securely random nonce for XChaCha20-Poly1305.

        Returns:
            bytes: A random nonce of length crypto_aead_xchacha20poly1305_ietf_NPUBBYTES.
        """
        return nacl.utils.random(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)

    @staticmethod
    def encrypt(
        plaintext: bytes,
        key: bytes,
        nonce: bytes,
        additional_data: bytes = None
    ) -> bytes:
        """
        Encrypt plaintext using XChaCha20-Poly1305.

        Args:
            plaintext (bytes): The data to encrypt.
            key (bytes): The encryption key (must be correct length).
            nonce (bytes): The nonce (must be correct length).
            additional_data (bytes, optional): Additional authenticated data (AAD). Defaults to None.

        Returns:
            bytes: The ciphertext (includes authentication tag).

        Raises:
            ValueError: If key or nonce are the wrong length.
        """
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
    def decrypt(
        ciphertext: bytes,
        key: bytes,
        nonce: bytes,
        additional_data: bytes = None
    ) -> bytes:
        """
        Decrypt ciphertext using XChaCha20-Poly1305.

        Args:
            ciphertext (bytes): The data to decrypt.
            key (bytes): The decryption key (must be correct length).
            nonce (bytes): The nonce (must be correct length).
            additional_data (bytes, optional): Additional authenticated data (AAD). Defaults to None.

        Returns:
            bytes: The decrypted plaintext.

        Raises:
            ValueError: If key, nonce, or ciphertext are the wrong length.
            RuntimeError: If decryption fails or message is forged.
        """
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