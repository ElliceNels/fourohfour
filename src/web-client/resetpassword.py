from session_manager import LoginSessionManager
from constants import GET_USER_ENDPOINT, RESET_PASSWORD_ENDPOINT
from key_utils import generate_salt, decrypt_and_reencrypt_user_file


def manage_reset_password(old_password, new_password):
    old_salt = get_salt()
    new_salt = generate_salt()
    username = LoginSessionManager.getInstance().getUsername()

    try:
        decrypt_and_reencrypt_user_file(username, old_password, old_salt, new_password, new_salt)
    except Exception as e:
        return False, f"Failed to encrypt and save key: {str(e)}"
    
    try:
        result = reset_password(new_password, new_salt)
        if result:
            return True, "Password reset successful!"
        else:
            return False, "Failed to reset password on server."
    except Exception as e:
        return False, f"Failed to reset password on server: {str(e)}"



def get_salt():

    try:
        response = LoginSessionManager.getInstance().get(GET_USER_ENDPOINT)
        if response is None:
            print("No response received from server")
            return False
            
        if response.ok:
            json_data = response.json()
            salt = json_data.get("salt")
            if salt:
                return salt
            else:
                print("No salt found in response")
                return False
        else:
            print(f"Server error: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"An error occurred while fetching salt: {str(e)}")
        return False
    


def reset_password(password, salt):
    data = {
        "new_password": password,
        "salt": salt
    }
    try:
        response = LoginSessionManager.getInstance().post(RESET_PASSWORD_ENDPOINT, data)
        print(f"Server response: {response}")
        
        if response is None:
            print("No response received from server")
            return False
            
        if response.ok:
            return True

    except Exception as e:
        print(f"An error occurred during registration: {str(e)}")
        return False