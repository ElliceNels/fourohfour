import nacl.pwhash
import nacl.exceptions

def hash_password(password: str) -> str:
    """
    Hash a password using Argon2id.

    Args:
        password (str): The plaintext password to hash.

    Returns:
        str: The hashed password as a utf-8 encoded string.
    """
    hashed = nacl.pwhash.argon2id.str(password.encode('utf-8'))
    return hashed.decode('utf-8')

def verify_password(hashed: str, password: str) -> str:
    """
    Verify a password against a given Argon2id hash.

    Args:
        hashed (str): The hashed password (utf-8 string).
        password (str): The plaintext password to verify.

    Returns:
        str: "Verification successful" if the password matches, otherwise "Failed verification".
    """
    try:
        nacl.pwhash.argon2id.verify(hashed.encode('utf-8'), password.encode('utf-8'))
        return "Verification successful"
    except nacl.exceptions.InvalidkeyError:
        return "Failed verification"