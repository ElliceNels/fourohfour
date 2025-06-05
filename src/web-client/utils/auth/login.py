from utils.auth.session_manager import LoginSessionManager
from constants import LOGIN_ENDPOINT
from exceptions import UserNotFoundError, InvalidPasswordError, ServerError

def manage_login(password, username):
    data = {
        "username": username,
        "password": password
    }
    try:
        response = LoginSessionManager.getInstance().post(LOGIN_ENDPOINT, data)
        
        json_data = response.json()
        access_token = json_data.get("access_token")
        refresh_token = json_data.get("refresh_token")
        
        if access_token and refresh_token:
            LoginSessionManager.getInstance().setTokens(access_token, refresh_token)
            LoginSessionManager.getInstance().setUsername(username)
            
            # Return additional SPK/OTPK status information from server response
            return True, "Login successful", {
                'spk_outdated': json_data.get('spk_outdated', False),
                'otpk_count_low': json_data.get('otpk_count_low', False),
                'unused_otpk_count': json_data.get('unused_otpk_count', 0)
            }
            
        return False, ServerError().message, None
        
    except UserNotFoundError as e:
        return False, "Invalid username or password", None
    except InvalidPasswordError as e:
        return False, "Invalid username or password", None
    except ServerError as e:
        return False, e.message, None
    except Exception as e:
        print(f"An error occurred during login: {e}")
        return False, ServerError().message, None