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
        try:
            return nacl.utils.random(crypto_aead_xchacha20poly1305_ietf_KEYBYTES)
        except Exception as e:
            raise Exception(f"Failed to generate encryption key: {str(e)}")

    @staticmethod
    def generate_nonce() -> bytes:
        """
        Generate a securely random nonce for XChaCha20-Poly1305.
        Returns:
            bytes: A random nonce of length crypto_aead_xchacha20poly1305_ietf_NPUBBYTES.
        Raises:
            Exception: If nonce generation fails for any reason.
        """
        try:
            return nacl.utils.random(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)
        except Exception as e:
            raise Exception(f"Failed to generate nonce: {str(e)}")

    @staticmethod
    def encrypt(plaintext: bytes, key: bytes, nonce: bytes, additional_data: bytes = None) -> bytes:
        """
        Encrypt plaintext using XChaCha20-Poly1305.
        Args:
            plaintext (bytes | str): The data to encrypt. If string, will be encoded to bytes using UTF-8.
            key (bytes | str): The encryption key (must be correct length). If string, will be encoded to bytes using UTF-8.
            nonce (bytes | str): The nonce (must be correct length). If string, will be encoded to bytes using UTF-8.
            additional_data (bytes | str, optional): Additional authenticated data (AAD). If string, will be encoded to bytes using UTF-8. Defaults to None.
        Returns:
            bytes: The ciphertext (includes authentication tag).
        Raises:
            ValueError: If key or nonce are the wrong length.
            TypeError: If any input cannot be converted to bytes.
            Exception: If encryption fails for any other reason.
        """
        try:
            try:
                plaintext = plaintext.encode('utf-8') if isinstance(plaintext, str) else plaintext
                key = key.encode('utf-8') if isinstance(key, str) else key
                nonce = nonce.encode('utf-8') if isinstance(nonce, str) else nonce
                additional_data = additional_data.encode('utf-8') if isinstance(additional_data, str) else additional_data
            except (AttributeError, UnicodeEncodeError) as e:
                raise TypeError(f"Failed to convert input to bytes: {str(e)}")

            if len(key) != crypto_aead_xchacha20poly1305_ietf_KEYBYTES:
                raise ValueError(f"Key must be {crypto_aead_xchacha20poly1305_ietf_KEYBYTES} bytes")
            if len(nonce) != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES:
                raise ValueError(f"Nonce must be {crypto_aead_xchacha20poly1305_ietf_NPUBBYTES} bytes")

            # Handle additional_data
            if additional_data is None:
                additional_data = b''

            ciphertext = crypto_aead_xchacha20poly1305_ietf_encrypt(
                plaintext,
                additional_data,
                nonce,
                key
            )
            return ciphertext
        except ValueError as ve:
            raise ve
        except TypeError as te:
            raise te
        except Exception as e:
            raise Exception(f"Encryption failed: {str(e)}")

    @staticmethod
    def decrypt(ciphertext: bytes, key: bytes, nonce: bytes, additional_data: bytes = None) -> bytes:
        """
        Decrypt ciphertext using XChaCha20-Poly1305.
        Args:
            ciphertext (bytes | str): The data to decrypt. If string, will be encoded to bytes using UTF-8.
            key (bytes | str): The decryption key (must be correct length). If string, will be encoded to bytes using UTF-8.
            nonce (bytes | str): The nonce (must be correct length). If string, will be encoded to bytes using UTF-8.
            additional_data (bytes | str, optional): Additional authenticated data (AAD). If string, will be encoded to bytes using UTF-8. Defaults to None.
        Returns:
            bytes: The decrypted plaintext.
        Raises:
            ValueError: If key, nonce, or ciphertext are the wrong length.
            TypeError: If any input cannot be converted to bytes.
            RuntimeError: If decryption fails or message is forged.
        """
        try:
            # Convert inputs to bytes if they are strings
            try:
                ciphertext = ciphertext.encode('utf-8') if isinstance(ciphertext, str) else ciphertext
                key = key.encode('utf-8') if isinstance(key, str) else key
                nonce = nonce.encode('utf-8') if isinstance(nonce, str) else nonce
                additional_data = additional_data.encode('utf-8') if isinstance(additional_data, str) else additional_data
            except (AttributeError, UnicodeEncodeError) as e:
                raise TypeError(f"Failed to convert input to bytes: {str(e)}")

            # Validate key and nonce lengths
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
                return plaintext
            except Exception as e:
                raise RuntimeError("Decryption failed or message forged") from e

        except ValueError as ve:
            raise ve
        except TypeError as te:
            raise te
        except RuntimeError as re:
            raise re
        except Exception as e:
            raise Exception(f"Decryption failed: {str(e)}")