import requests
from config import config

class ServerAPI:
    def __init__(self, base_url=config.server.url, session=None):
        self.base_url = base_url.rstrip('/')
        self.session = session or requests.Session()
        self.refresh_token = None

    def set_bearer_token(self, token, refresh_token=None):
        """Set the Bearer token for Authorization header and optionally the refresh token."""
        self.session.headers.update({"Authorization": f"Bearer {token}"})
        if refresh_token:
            self.refresh_token = refresh_token

    def get_current_user(self):
        """GET /get_current_user - Returns current user info."""
        url = f"{self.base_url}/get_current_user"
        try:
            resp = self.session.get(url)
            return resp.json(), resp.status_code
        except Exception as e:
            return {"error": str(e)}, 500

    def get_public_key(self, username):
        """GET /get_public_key?username=<username> - Get a user's public key."""
        url = f"{self.base_url}/get_public_key"
        try:
            resp = self.session.get(url, params={"username": username})
            return resp.json(), resp.status_code
        except Exception as e:
            return {"error": str(e)}, 500

    def refresh_access_token(self):
        """POST /refresh - Refresh the access session token using the refresh token."""
        if not self.refresh_token:
            return {"error": "No refresh token set."}, 401
        url = f"{self.base_url}/refresh"
        try:
            resp = self.session.post(url, json={"refresh_token": self.refresh_token})
            if resp.status_code == 200:
                data = resp.json()
                access_token = data.get("access_token")
                refresh_token = data.get("refresh_token")
                if access_token:
                    self.set_bearer_token(access_token, refresh_token or self.refresh_token)
                return data, resp.status_code
            else:
                return resp.json(), resp.status_code
        except Exception as e:
            return {"error": str(e)}, 500