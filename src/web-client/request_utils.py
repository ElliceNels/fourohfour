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

def post_request(url, json_data=None):
    """
    Make a POST request (HTTP or HTTPS) with exception handling.
    :param url: The URL to send the POST request to.
    :param json_data: (Optional) JSON data to send in the body.
    :return: Response object or None if an error occurs.
    :raises: UsernameAlreadyExistsError, UserNotFoundError, InvalidPasswordError, ServerError
    """
    try:
        if json_data is not None and isinstance(json_data, dict):
            response = requests.post(
                url,
                data=json.dumps(json_data),
                headers={'Content-Type': 'application/json'}
            )
        else:
            response = requests.post(url, data=json_data)
            
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