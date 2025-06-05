import os
import json
import tkinter as tk
from tkinter import filedialog
from typing import Tuple, Optional
import base64
from nacl.public import PrivateKey
from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
    crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
)
import nacl.utils
from nacl import pwhash
from utils.encryption_helper import EncryptionHelper  
from utils.auth.session_manager import LoginSessionManager
from constants import BINARY_EXTENSION, KEYS_PATH, MASTER_KEY_PATH
import os
from nacl.signing import SigningKey

def generate_sodium_keypair() -> tuple[str, str]:
    """
    Generate an Ed25519 public/private keypair using libsodium (PyNaCl) and return as base64-encoded strings.

    Returns:
        tuple[str, str]: (public_key_base64, private_key_base64)
    """
    signing_key = SigningKey.generate()
    verify_key = signing_key.verify_key
    
    public_b64 = base64.b64encode(bytes(verify_key)).decode('utf-8')
    private_b64 = base64.b64encode(bytes(signing_key)).decode('utf-8')
    
    return public_b64, private_b64


def encrypt_and_save_key(private_key_b64: str, derived_key: bytes, username: str) -> bool:
    """
    Encrypt the private key with a random key, then encrypt that key with the derived key.
    Save both to files.

    Args:
        private_key_b64 (str): Base64-encoded private key.
        derived_key (bytes): Key derived from the user's password.
        username (str): Username for file naming.

    Returns:
        bool: True if successful, False otherwise.
    """
    #Prepare JSON
    json_data = json.dumps({"privateKey": private_key_b64}).encode('utf-8')

    #Generate random key and nonce
    key = EncryptionHelper.generate_key()
    nonce = EncryptionHelper.generate_nonce()

    #Encrypt private key JSON
    ciphertext = EncryptionHelper.encrypt(json_data, key, nonce)

    #Prepare data: [nonce][ciphertext]
    combined_data = nonce + ciphertext

    #Save encrypted private key file
    file_name = f"{KEYS_PATH}{username}{BINARY_EXTENSION}"
    try:
        with open(file_name, 'wb') as f:
            f.write(combined_data)
    except IOError as e:
        print(f"Error saving encrypted key file: {str(e)}")
        return False

    #Encrypt and save master key
    if not encrypt_and_save_master_key(key, derived_key, username):
        print("Error saving encrypted key file")
        return False

    return True

def encrypt_and_save_master_key(key_to_encrypt: bytes, derived_key: bytes, username: str) -> bool:
    """
    Encrypt the random key with the derived key and save to file.

    Args:
        key_to_encrypt (bytes): The random key to encrypt.
        derived_key (bytes): The key derived from the user's password.
        username (str): Username for file naming.

    Returns:
        bool: True if successful, False otherwise.
    """
    nonce = EncryptionHelper.generate_nonce()
    LoginSessionManager.getInstance().setMasterKey(derived_key)
    encrypted_key = EncryptionHelper.encrypt(key_to_encrypt, derived_key, nonce)
    combined_data = nonce + encrypted_key

    file_path = f"{MASTER_KEY_PATH}{username}{BINARY_EXTENSION}"
    try:
        with open(file_path, 'wb') as f:
            f.write(combined_data)
        return True
    except IOError as e:
        print(f"Error saving master key file: {str(e)}")
        return False 
    


def decrypt_and_reencrypt_user_file(username: str, old_password: str, old_salt: bytes, new_password: str, new_salt: bytes) -> bool:
    """
    Decrypt a user's encrypted file using their old password and salt, then re-encrypt it with their new password and salt.

    Args:
        username (str): The username of the user
        old_password (str): The user's old password
        old_salt (bytes): The user's old salt (already decoded from base64)
        new_password (str): The user's new password
        new_salt (bytes): The user's new salt (already decoded from base64)

    Returns:
        bool: True if successful, False otherwise
    """
    crypto = EncryptionHelper()

    # Read encrypted file
    file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), f"{MASTER_KEY_PATH}{username}{BINARY_EXTENSION}")
    try:
        with open(file_path, 'rb') as file:
            encrypted_data = file.read()
    except IOError as e:
        print(f"Failed to open file for reading: {file_path}")
        return False

    # Extract nonce and ciphertext
    nonce_size = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
    nonce = encrypted_data[:nonce_size]  
    ciphertext = encrypted_data[nonce_size:] 

    # Derive old key
    old_key = derive_key_from_password(old_password, old_salt)

    # Decrypt
    try:
        decrypted_data = crypto.decrypt(
            ciphertext,
            old_key,
            nonce,
            None  # no additional data
        )
    except Exception as e:
        print(f"Decryption failed: {str(e)}")
        return False

    # Derive new key
    new_key = derive_key_from_password(new_password, new_salt)

    # Re-encrypt and save
    return encrypt_and_save_master_key(decrypted_data, new_key, username)

def derive_key_from_password(password: str, salt: bytes, key_len: int = 32) -> bytes:
    """
    Derive a key from a password and salt using Argon2id.

    Args:
        password (str): The password to derive the key from.
        salt (bytes): The salt to use for key derivation.
        key_len (int, optional): Desired key length in bytes. Defaults to 32.

    Returns:
        bytes: The derived key.
    """
    opslimit = pwhash.argon2id.OPSLIMIT_INTERACTIVE
    memlimit = pwhash.argon2id.MEMLIMIT_INTERACTIVE
    return pwhash.argon2id.kdf(key_len, password.encode('utf-8'), salt, opslimit=opslimit, memlimit=memlimit)

def generate_salt(length: int = pwhash.argon2id.SALTBYTES) -> str:
    """
    Generate a random salt and return it as a base64-encoded string.

    Args:
        length (int): Length of the salt in bytes. Defaults to pwhash.argon2id.SALTBYTES.

    Returns:
        str: Base64-encoded salt.
    """
    salt = nacl.utils.random(length)
    salt_b64 = base64.b64encode(salt).decode('utf-8')
    return salt_b64

def decode_salt(salt_b64: str) -> bytes:
    """
    Decode a base64-encoded salt string back to bytes.

    Args:
        salt_b64 (str): Base64-encoded salt.

    Returns:
        bytes: The decoded salt.
    """
    return base64.b64decode(salt_b64)