from session_manager import LoginSessionManager
from constants import LOGIN_ENDPOINT
from exceptions import UserNotFoundError, InvalidPasswordError

def manage_login(password, username):
    data = {
        "username": username,
        "password": password
    }
    try:
        response = LoginSessionManager.getInstance().post(LOGIN_ENDPOINT, data)
        if response is not None and response.ok:
            json_data = response.json()
            access_token = json_data.get("access_token")
            refresh_token = json_data.get("refresh_token")
            if access_token and refresh_token:
                LoginSessionManager.getInstance().setTokens(access_token, refresh_token)
                LoginSessionManager.getInstance().setUsername(username)
                return True
        elif response.status_code == 404:
            raise UserNotFoundError("User not found.")
        elif response.status_code == 401:
            raise InvalidPasswordError("Invalid password.")
        return False
    except UserNotFoundError as e:
        raise e
    except InvalidPasswordError as e:
        raise e
    except Exception as e:
        print(f"An error occurred during login: {e}")
        return False