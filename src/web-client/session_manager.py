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

        return post_request(path, data)
    
    def get(self, url: str, params: dict = None):
        path = SERVER_URL + url
        access_token, refresh_token = self.access_token, self.refresh_token
        print(f"Access Token: {access_token}")
        print(f"Refresh Token: {refresh_token}")

        access_exp, access_exp_datetime = get_jwt_exp(access_token)
        refresh_exp, refresh_exp_datetime = get_jwt_exp(refresh_token)

        print(f"Access Token exp: {access_exp} ({access_exp_datetime} UTC)")
        print(f"Refresh Token exp: {refresh_exp} ({refresh_exp_datetime} UTC)")
        return get_request(path, refresh_token, access_token, params)

    def clearSession(self):
        if self.masterKey:
            self.masterKey = b'\x00' * len(self.masterKey)
            self.masterKey = None
        self.username = None
        self.access_token = None
        self.refresh_token = None
        print("Session cleaned up when called")


import base64
import json
import datetime

def get_jwt_exp(token):
    # JWT format: header.payload.signature
    try:
        payload_part = token.split('.')[1]
        # Pad base64 string if necessary
        padding = '=' * (-len(payload_part) % 4)
        payload_part += padding
        decoded = base64.urlsafe_b64decode(payload_part)
        payload = json.loads(decoded)
        exp = payload.get('exp')
        if exp:
            exp_datetime = datetime.datetime.utcfromtimestamp(exp)
            return exp, exp_datetime
        else:
            return None, None
    except Exception as e:
        print(f"Error decoding token: {e}")
        return None, None