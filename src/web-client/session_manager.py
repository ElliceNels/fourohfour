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
        self.username: Optional[str] = None
        self.masterKey: Optional[bytes] = None
        self.access_token: Optional[str] = None
        self.refresh_token: Optional[str] = None
        self.jwt_token: Optional[str] = None

    @classmethod
    def getInstance(cls):
        return cls()

    def setSession(self, username: str, masterKey: bytes):
        self.clearSession()
        self.username = username
        self.masterKey = masterKey

    def getUsername(self) -> Optional[str]:
        return self.username
    
    def setUsername(self, username: str):
        self.username = username

    def getMasterKey(self) -> Optional[bytes]:
        return self.masterKey if self.masterKey else None
    
    def setMasterKey(self, masterKey: str):
        self.masterKey = masterKey

    def getJwtToken(self) -> Optional[str]:
        return self.jwt_token
    
    def setJwtToken(self, token: str):
        self.jwt_token = token

    def setTokens(self, accessToken: str, refreshToken: str):
        self.access_token = accessToken
        self.refresh_token = refreshToken

    def getTokens(self):
        return self.access_token, self.refresh_token

    def post(self, url: str, data: dict):
        path = SERVER_URL + url
        access_token, refresh_token = self.getTokens()
    
        
        return post_request(path, data, access_token, refresh_token)
    
    def get(self, url: str, params: dict = None):
        path = SERVER_URL + url
        access_token, refresh_token = self.access_token, self.refresh_token

        return get_request(path, access_token, refresh_token, params)

    def clearSession(self):
        if self.masterKey:
            self.masterKey = b'\x00' * len(self.masterKey)
            self.masterKey = None
        self.username = None
        self.access_token = None
        self.refresh_token = None
        print("Session cleaned up when called")