import requests
import json
from exceptions import UsernameAlreadyExistsError, ServerError, UserNotFoundError, InvalidPasswordError
from constants import SERVER_URL, GET_USER_ENDPOINT
from session_manager import LoginSessionManager

def get_request(url, access_token, refresh_token, params=None):
    """
    Make a GET request (HTTP or HTTPS) with exception handling.
    :param url: The URL to send the GET request to.
    :param params: (Optional) Dictionary of URL parameters.
    :return: Response object or None if an error occurs.
    """
    try:
        if params is not None and isinstance(params, dict):
            params = {'data': json.dumps(params)}
        
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



path = SERVER_URL + GET_USER_ENDPOINT
access_token, refresh_token = LoginSessionManager.getInstance().getTokens()

response = get_request(path, access_token, refresh_token, None)
jresponse = response.json()
print(response)
print(jresponse)