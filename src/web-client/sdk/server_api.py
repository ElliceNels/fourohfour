import requests
from config import config

class ServerAPI:
    def __init__(self, base_url=config.server.url, session=None):
        self.base_url = base_url.rstrip('/')
        self.session = session or requests.Session()

    def set_bearer_token(self, token):
        """Set the Bearer token for Authorization header."""
        self.session.headers.update({"Authorization": f"Bearer {token}"})

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