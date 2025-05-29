import os
import json
import base64
from nacl.public import PrivateKey
from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
    crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
)
import nacl.utils
from nacl import pwhash
from encryption_helper import EncryptionHelper  
from constants import BINARY_EXTENSION

def generate_sodium_keypair():
    """
    Generate a public/private keypair and return as base64 strings.
    """
    private_key = PrivateKey.generate()
    public_key = private_key.public_key
    public_b64 = base64.b64encode(bytes(public_key)).decode('utf-8')
    private_b64 = base64.b64encode(bytes(private_key)).decode('utf-8')
    return public_b64, private_b64

def save_keys_to_json_file(public_key_b64, private_key_b64, filename):
    """
    Save public and private keys (base64) to a JSON file.
    """
    data = {
        "publicKey": public_key_b64,
        "privateKey": private_key_b64
    }
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)
    return True

def encrypt_and_save_key(private_key_b64, derived_key, username):
    """
    Encrypt the private key with a random key, then encrypt that key with the derived key.
    Save both to files.
    """
    # Prepare JSON
    json_data = json.dumps({"privateKey": private_key_b64}).encode('utf-8')

    # Generate random key and nonce
    key = EncryptionHelper.generate_key()
    nonce = EncryptionHelper.generate_nonce()

    # Encrypt private key JSON
    ciphertext = EncryptionHelper.encrypt(json_data, key, nonce)

    # Prepare data: [nonce][ciphertext]
    combined_data = nonce + ciphertext

    # Save encrypted private key file
    file_name = f"./keys_{username}{BINARY_EXTENSION}"
    with open(file_name, 'wb') as f:
        f.write(combined_data)

    # Encrypt and save master key
    if not encrypt_and_save_master_key(key, derived_key, username):
        print("Error saving encrypted key file")
        return False

    return True

def encrypt_and_save_master_key(key_to_encrypt, derived_key, username):
    """
    Encrypt the random key with the derived key and save to file.
    """
    nonce = EncryptionHelper.generate_nonce()
    encrypted_key = EncryptionHelper.encrypt(key_to_encrypt, derived_key, nonce)
    combined_data = nonce + encrypted_key

    file_path = f"./masterKey_{username}{BINARY_EXTENSION}"
    with open(file_path, 'wb') as f:
        f.write(combined_data)
    return True

def derive_key_from_password(password: str, salt: bytes, key_len: int = 32) -> bytes:
    opslimit = pwhash.argon2id.OPSLIMIT_INTERACTIVE
    memlimit = pwhash.argon2id.MEMLIMIT_INTERACTIVE
    return pwhash.argon2id.kdf(key_len, password.encode('utf-8'), salt, opslimit=opslimit, memlimit=memlimit)

def generate_salt(length: int = pwhash.argon2id.SALTBYTES) -> str:
    """
    Generate a random salt and return it as a base64-encoded string.
    """
    salt = nacl.utils.random(length)
    salt_b64 = base64.b64encode(salt).decode('utf-8')
    return salt_b64

def decode_salt(salt_b64: str) -> bytes:
    """
    Decode a base64-encoded salt string back to bytes.
    """
    return base64.b64decode(salt_b64)
