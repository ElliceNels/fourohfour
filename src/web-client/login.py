from session_manager import LoginSessionManager
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
            return True, "Login successful"
            
        return False, ServerError().message
        
    except UserNotFoundError as e:
        return False, e.message
    except InvalidPasswordError as e:
        return False, e.message
    except ServerError as e:
        return False, e.message
    except Exception as e:
        print(f"An error occurred during login: {e}")
        return False, ServerError().message