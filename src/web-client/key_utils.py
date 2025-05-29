import os
import json
import base64
from nacl.public import PrivateKey
from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
    crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
)
import nacl.utils
from encryption_helper import EncryptionHelper  # Make sure this file is in your project

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

def encrypt_and_save_key(private_key_b64, derived_key, username, keys_path, binary_extension):
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
    file_name = os.path.join(keys_path, f"{username}{binary_extension}")
    with open(file_name, 'wb') as f:
        f.write(combined_data)

    # Encrypt and save master key
    if not encrypt_and_save_master_key(key, derived_key, username, keys_path, binary_extension):
        print("Error saving encrypted key file")
        return False

    return True

def encrypt_and_save_master_key(key_to_encrypt, derived_key, username, keys_path, binary_extension):
    """
    Encrypt the random key with the derived key and save to file.
    """
    nonce = EncryptionHelper.generate_nonce()
    encrypted_key = EncryptionHelper.encrypt(key_to_encrypt, derived_key, nonce)
    combined_data = nonce + encrypted_key

    file_path = os.path.join(keys_path, f"master_{username}{binary_extension}")
    with open(file_path, 'wb') as f:
        f.write(combined_data)
    return True


def derive_key_from_password(password: str, salt: bytes, key_len: int = nacl.pwhash.argon2id.OUTLEN) -> bytes:
    """
    Derive a key from a password and salt using Argon2id (interactive limits).
    Returns the derived key as bytes.
    """
    opslimit = nacl.pwhash.argon2id.OPSLIMIT_INTERACTIVE
    memlimit = nacl.pwhash.argon2id.MEMLIMIT_INTERACTIVE
    return nacl.pwhash.argon2id.kdf(key_len, password.encode('utf-8'), salt, opslimit=opslimit, memlimit=memlimit)

def generate_salt(length: int = nacl.pwhash.SALTBYTES) -> str:
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


# Generate keypair
pub_b64, priv_b64 = generate_sodium_keypair()
print("Public:", pub_b64)
print("Private:", priv_b64)

# Save to JSON
save_keys_to_json_file(pub_b64, priv_b64, "mykeys.json")

# Example: Encrypt and save key (simulate derived_key)
derived_key = nacl.utils.random(crypto_aead_xchacha20poly1305_ietf_KEYBYTES)
encrypt_and_save_key(priv_b64, derived_key, "alice", "./", ".bin")