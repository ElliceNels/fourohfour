from typing import Optional
from config import config
import requests
import json
from exceptions import UsernameAlreadyExistsError, ServerError, UserNotFoundError, InvalidPasswordError, SamePasswordError

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
        self.SERVER_URL = config.server.url

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
        path = self.SERVER_URL + url
        access_token, refresh_token = self.getTokens()
    
        
        return post_request(path, data, access_token, refresh_token)
    
    def get(self, url: str, params: dict = None):
        path = self.SERVER_URL + url
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

def get_request(url, access_token, refresh_token, params=None):
    """
    Make a GET request (HTTP or HTTPS) with exception handling.
    :param url: The URL to send the GET request to.
    :param params: (Optional) Dictionary of URL parameters.
    :return: Response object or None if an error occurs.
    """
    try:
        # Do NOT wrap or encode params for GET requests
        headers = {}
        if access_token:
            headers['Authorization'] = f'Bearer {access_token}'
        if refresh_token:
            headers['X-Refresh-Token'] = refresh_token  

        response = requests.get(url, params=params, headers=headers)
        response.raise_for_status()
        return response
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred: {http_err}")
    except requests.exceptions.ConnectionError as conn_err:
        print(f"Connection error occurred: {conn_err}")
    except requests.exceptions.Timeout as timeout_err:
        print(f"Timeout error occurred: {timeout_err}")
    except requests.exceptions.RequestException as req_err:
        print(f"An error occurred: {req_err}")
    return None

def post_request(url, json_data=None, access_token=None, refresh_token=None):
    """
    Make a POST request (HTTP or HTTPS) with exception handling.
    :param url: The URL to send the POST request to.
    :param json_data: (Optional) JSON data to send in the body.
    :param access_token: (Optional) JWT access token for authentication.
    :param refresh_token: (Optional) JWT refresh token for authentication.
    :return: Response object or None if an error occurs.
    """
    try:
        headers = {'Content-Type': 'application/json'}
        
        # Add authentication headers
        if access_token:
            headers['Authorization'] = f'Bearer {access_token}'
        if refresh_token:
            headers['X-Refresh-Token'] = refresh_token

        if json_data is not None and isinstance(json_data, dict):
            response = requests.post(
                url,
                data=json.dumps(json_data),
                headers=headers
            )
        else:
            response = requests.post(url, data=json_data, headers=headers)
            
        # Check status codes before raise_for_status
        if response.status_code == 409:
            raise UsernameAlreadyExistsError()
        elif response.status_code == 404:
            raise UserNotFoundError()
        elif response.status_code == 401:
            raise InvalidPasswordError()
        elif response.status_code == 400:
            raise SamePasswordError()
            
        response.raise_for_status()
        return response
        
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred: {http_err}")
        if "409" in str(http_err):
            raise UsernameAlreadyExistsError()
        elif "404" in str(http_err):
            raise UserNotFoundError()
        elif "401" in str(http_err):
            raise InvalidPasswordError()
        elif "400" in str(http_err):
            raise SamePasswordError()
        raise ServerError()
    except requests.exceptions.ConnectionError as conn_err:
        print(f"Connection error occurred: {conn_err}")
        raise ServerError()
    except requests.exceptions.Timeout as timeout_err:
        print(f"Timeout error occurred: {timeout_err}")
        raise ServerError()
    except requests.exceptions.RequestException as req_err:
        print(f"An error occurred: {req_err}")
        raise ServerError()