from session_manager import LoginSessionManager
from constants import LOGIN_ENDPOINT

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
                return True
        return False
    except Exception as e:
        print(f"An error occurred during login: {e}")
        return False