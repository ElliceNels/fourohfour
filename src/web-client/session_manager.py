from request_utils import post_request, get_request
from typing import Optional
import os
from constants import SERVER_URL

class LoginSessionManager:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(LoginSessionManager, cls).__new__(cls)
            cls._instance._init()
        return cls._instance

    def _init(self):
        self.m_username: Optional[str] = None
        self.m_masterKey: Optional[bytes] = None
        self.access_token: Optional[str] = None
        self.refresh_token: Optional[str] = None

    @classmethod
    def getInstance(cls):
        return cls()

    def setSession(self, username: str, masterKey: bytes):
        self.clearSession()
        self.m_username = username
        self.m_masterKey = masterKey

    def getUsername(self) -> Optional[str]:
        return self.m_username

    def getMasterKey(self) -> Optional[bytes]:
        return self.m_masterKey if self.m_masterKey else None

    def setTokens(self, accessToken: str, refreshToken: str):
        self.access_token = accessToken
        self.refresh_token = refreshToken

    def post(self, url: str, data: dict):
        path = SERVER_URL + url

        return post_request(path, data)
    
    def get(self, url: str, params: dict = None):
        path = os.path.join(SERVER_URL, url)
        return get_request(path, params)

    def clearSession(self):
        if self.m_masterKey:
            self.m_masterKey = b'\x00' * len(self.m_masterKey)
            self.m_masterKey = None
        self.m_username = None
        self.access_token = None
        self.refresh_token = None
        print("Session cleaned up when called")