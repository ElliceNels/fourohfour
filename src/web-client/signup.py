import unicodedata
from key_utils import generate_sodium_keypair, save_keys_to_json_file, encrypt_and_save_key, derive_key_from_password, generate_salt, decode_salt
from session_manager import LoginSessionManager
from constants import SIGN_UP_ENDPOINT
from exceptions import UsernameAlreadyExistsError, ServerError

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
    try:
        #Generate keypair
        try:
            pub_b64, priv_b64 = generate_sodium_keypair()
        except Exception as e:
            return False, f"Failed to generate keypair: {str(e)}"

        #Save public key
        try:
            save_keys_to_json_file(pub_b64, priv_b64)
        except Exception as e:
            return False, f"Failed to save keys to file: {str(e)}"

        #Generate and decode salt
        try:
            salt = generate_salt()
            raw_salt = decode_salt(salt)
        except Exception as e:
            return False, f"Failed to generate or decode salt: {str(e)}"

        #Derive key from password
        try:
            derived_key = derive_key_from_password(password, raw_salt)
        except Exception as e:
            return False, f"Failed to derive key from password: {str(e)}"

        #Encrypt and save private key
        try:
            encrypt_and_save_key(priv_b64, derived_key, account_name)
        except Exception as e:
            return False, f"Failed to encrypt and save key: {str(e)}"

        return True, "Registration completed successfully"

    except Exception as e:
        # Catch any unexpected errors
        return False, f"Unexpected error during registration: {str(e)}"
    
def register_user(username, password, public_key, salt):
    data = {
        "username": username,
        "password": password,
        "public_key": public_key,
        "salt": salt
    }
    try:
        response = LoginSessionManager.getInstance().post(SIGN_UP_ENDPOINT, data)
        if response is not None and response.ok:
            json_data = response.json()
            jwt_token = json_data.get("token")
            if jwt_token:
                LoginSessionManager.getInstance().setJwtToken(jwt_token)
                return True
        elif response.status_code == 409:  
            raise UsernameAlreadyExistsError("Username already exists.")
        elif response.status_code >= 500:  
            raise ServerError("Server error occurred.")
        return False
    except UsernameAlreadyExistsError as e:
        raise e
    except ServerError as e:
        raise e
    except Exception as e:
        print(f"An error occurred during registration: {e}")
        return False



