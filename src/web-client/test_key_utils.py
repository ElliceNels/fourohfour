import base64
import nacl.utils
from nacl import pwhash
from nacl.bindings import (
    crypto_box_PUBLICKEYBYTES,
    crypto_box_SECRETKEYBYTES,
    crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
    crypto_pwhash_SALTBYTES,
)
import re
from key_utils import generate_sodium_keypair, generate_salt, decode_salt, derive_key_from_password, encrypt_and_save_key, encrypt_and_save_master_key, decrypt_and_reencrypt_user_file


def test_generate_sodium_keypair():
    pub, priv = generate_sodium_keypair()
    assert isinstance(pub, str)
    assert isinstance(priv, str)
    assert pub != priv
    assert len(pub) > 0
    assert len(priv) > 0

def test_generate_sodium_keypair_length():
    pub, priv = generate_sodium_keypair()
    pub_bytes = base64.b64decode(pub)
    priv_bytes = base64.b64decode(priv)
    assert len(pub_bytes) == crypto_box_PUBLICKEYBYTES
    assert len(priv_bytes) == crypto_box_SECRETKEYBYTES

def test_generate_sodium_keypair_format():
    pub, priv = generate_sodium_keypair()
    base64_pattern = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
    assert base64_pattern.match(pub)
    assert base64_pattern.match(priv)

def test_generate_salt():
    salt1 = generate_salt()
    assert isinstance(salt1, str)
    base64_pattern = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
    assert base64_pattern.match(salt1)
    decoded = base64.b64decode(salt1)
    assert len(decoded) == crypto_pwhash_SALTBYTES
    salt2 = generate_salt()
    assert salt1 != salt2

def test_generate_salt_custom_length():
    custom_length = 32
    salt = generate_salt(custom_length)
    base64_pattern = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
    assert base64_pattern.match(salt)
    decoded = base64.b64decode(salt)
    assert len(decoded) == custom_length

def test_derive_key_from_password():
    password = "testPassword123!"
    salt = nacl.utils.random(crypto_pwhash_SALTBYTES)
    key = derive_key_from_password(password, salt)
    assert isinstance(key, bytes)
    assert len(key) == crypto_aead_xchacha20poly1305_ietf_KEYBYTES
    assert any(b != 0 for b in key)

def test_derive_key_from_password_consistency():
    password = "testPassword123!"
    salt = nacl.utils.random(crypto_pwhash_SALTBYTES)
    key1 = derive_key_from_password(password, salt)
    key2 = derive_key_from_password(password, salt)
    assert key1 == key2

def test_derive_key_from_password_different_salts():
    password = "testPassword123!"
    salt1 = nacl.utils.random(crypto_pwhash_SALTBYTES)
    salt2 = nacl.utils.random(crypto_pwhash_SALTBYTES)
    key1 = derive_key_from_password(password, salt1)
    key2 = derive_key_from_password(password, salt2)
    assert key1 != key2

def test_derive_key_from_password_empty_password():
    password = ""
    salt = nacl.utils.random(crypto_pwhash_SALTBYTES)
    key = derive_key_from_password(password, salt)
    assert isinstance(key, bytes)
    assert len(key) == crypto_aead_xchacha20poly1305_ietf_KEYBYTES
    assert any(b != 0 for b in key)

def test_decrypt_and_reencrypt_user_file_wrong_password(tmp_path):
    # Setup: create a file with a known password
    global MASTER_KEY_PATH, BINARY_EXTENSION
    MASTER_KEY_PATH = str(tmp_path) + "/"
    BINARY_EXTENSION = ".bin"
    username = "user"
    password = "correct"
    salt = nacl.utils.random(16)
    new_password = "newpass"
    new_salt = nacl.utils.random(16)
    key = derive_key_from_password(password, salt)
    # Save a master key file
    encrypt_and_save_master_key(b"secretdata", key, username)
    # Try to decrypt with wrong password
    result = decrypt_and_reencrypt_user_file(username, "wrong", salt, new_password, new_salt)
    assert result is False

def test_generate_salt_zero_length():
    salt = generate_salt(0)
    assert salt == ""
