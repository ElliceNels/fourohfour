import requests
import json
from exceptions import UsernameAlreadyExistsError, ServerError, UserNotFoundError, InvalidPasswordError

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