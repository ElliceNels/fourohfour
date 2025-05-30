import unicodedata
from key_utils import generate_sodium_keypair, save_keys_to_json_file, encrypt_and_save_key, derive_key_from_password, generate_salt, decode_salt
from password_utils import hash_password

RESTRICTED_CHARS = set('!@#$%^&*()+=[]{}|\\;:\'",<>/?`~')  

def load_dictionary_words(filepath):
    with open(filepath, encoding='utf-8') as f:
        return set(line.strip().lower() for line in f if line.strip())

def validate_registration(account_name, password, confirm_password):
    dictionary_words = load_dictionary_words('common_passwords.txt')

    if password != confirm_password:
        return False, "Passwords do not match!"
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if len(password) > 64:
        return False, "Password must be no more than 64 characters long."
    if not account_name.strip():
        return False, "Username cannot be empty or only spaces."
    if not password.strip():
        return False, "Password cannot be empty or only spaces."
    if password.lower() == account_name.lower():
        return False, "Password cannot be the same as your username."
    if password != unicodedata.normalize('NFKC', password):
        return False, "Your password contains characters that may look different on other devices."
    if password.lower() in dictionary_words:
        return False, "Password is too common or easily guessable."
    if any(char in RESTRICTED_CHARS for char in account_name):
        return False, "Username contains invalid characters. Please use only letters, numbers, underscores, and hyphens."

    return True, "Account created successfully!"

def manage_registration(account_name, password):
    pub_b64, priv_b64 = generate_sodium_keypair()
    save_keys_to_json_file(pub_b64, priv_b64, "./mykeys.json")

    hashed = hash_password(password)

    salt = generate_salt()
    raw_salt = decode_salt(salt)

    derived_key = derive_key_from_password(password, raw_salt)

    encrypt_and_save_key(priv_b64, derived_key, account_name)



