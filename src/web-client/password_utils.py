import nacl.pwhash
import nacl.exceptions

def hash_password(password: str) -> str:
    """
    Hash a password using Argon2id (interactive limits).
    Returns the hash as a utf-8 string.
    """
    hashed = nacl.pwhash.argon2id.str(password.encode('utf-8'))
    return hashed.decode('utf-8')

def verify_password(hashed: str, password: str) -> str:
    """
    Verify a password against a hash.
    Returns a string indicating success or failure.
    """
    try:
        nacl.pwhash.argon2id.verify(hashed.encode('utf-8'), password.encode('utf-8'))
        return "Verification successful"
    except nacl.exceptions.InvalidkeyError:
        return "Failed verification"
    