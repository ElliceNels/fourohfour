from session_manager import LoginSessionManager
from constants import GET_USER_ENDPOINT, RESET_PASSWORD_ENDPOINT
from key_utils import generate_salt, decrypt_and_reencrypt_user_file
import base64


def manage_reset_password(old_password, new_password):
    old_salt_b64 = get_salt()
    new_salt_b64 = generate_salt()

    old_salt = base64.b64decode(old_salt_b64)
    new_salt = base64.b64decode(new_salt_b64)


    username = LoginSessionManager.getInstance().getUsername()

    print("Decrytping local files")
    if (decrypt_and_reencrypt_user_file(username, old_password, old_salt, new_password, new_salt) == False):
        return False, "Failed to encrypt and save key"

    
    try:
        print("Calling reset password")
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
                salt = base64.b64decode(salt)
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

    salt = base64.b64encode(salt).decode('utf-8')

    print("Preapring data")
    data = {
        "new_password": password,
        "salt": salt
    }
    try:
        print("Sending to server")
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