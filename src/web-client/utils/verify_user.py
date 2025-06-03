import hashlib
from sdk.server_api import ServerAPI
import json
from config import config
import logging
from pathlib import Path

logger = logging.getLogger(__name__)
serv_api = ServerAPI()

def generate_code(friend_username: str) -> str:
    """Generate a code using my public key and friend's public key."""

    # Get friend's public key from the server
    pk_info, status = serv_api.get_public_key(friend_username)
    if status != 200:
        logger.error("Failed to fetch friend's public key")
        raise Exception("Failed to fetch friend's public key")
    friend_pk = pk_info.get("public_key")
    if not friend_pk:
        logger.error("Public key not found in response")
        raise Exception("Public key not found in response")
    
    # Get my public key from the friend file
    my_username = _get_current_username()
    friends_data = _load_friend_file()
    if friends_data and friend_in_friends(my_username):
        my_pk = friends_data[my_username]
    else:
        logger.error(f"My public key not found in friends for username {my_username}")
        raise Exception(f"My public key not found in friends for username {my_username}")
    
    # Combine with public keys
    if (friend_pk > my_pk):
        combined_pks = my_pk + friend_pk
    else:
        combined_pks = friend_pk + my_pk
    combined_code = hashlib.sha256(combined_pks.encode()).hexdigest()

    logger.info(f"Generated code: {combined_code} using my_pk and friend_pk")
    return combined_code

def _get_current_username() -> str:
    """Get the current username from the server."""
    user_info, status = serv_api.get_current_user()
    if status != 200:
        logger.error("Failed to fetch current user info")
        raise Exception("Failed to fetch current user info")
    username = user_info.get("username")
    if not username:
        logger.error("Username not found in user info")
        raise Exception("Username not found in user info")
    return username

def _get_friend_filepath() -> str:
    """Get the path to the friend file."""
    try:
        path = Path(config.friends.file_path + "_" + _get_current_username() + config.friends.extension)
        return path
    except Exception as e:
        logger.error(f"Error getting friend file path: {e}")
        raise Exception(f"Error getting friend file path: {e}") 

def friend_file_exists() -> bool | None:
    """Check if the friend file exists."""
    try:
        with open(_get_friend_filepath(), 'r') as f:
            logger.debug(f"File {_get_friend_filepath()} exists")
            return True
    except FileNotFoundError:
        logger.debug(f"Friend file not found at {_get_friend_filepath()}")
        return False
    except json.JSONDecodeError:
        logger.error(f"Error checking for friend file at {_get_friend_filepath()}")
        return None

def _create_friend_file() -> bool:
    """Create an empty friend file, adding your public key if it doesn't exist."""

    # Check if the friend file already exists
    if friend_file_exists() is True:
        logger.info("Friend file already exists, skipping creation")
        return True

    # Retrieve my username and public key from the server
    user_info, status = serv_api.get_current_user()
    if status != 200:
        raise Exception("Failed to fetch current user info")
    if not user_info or "username" not in user_info or "public_key" not in user_info:
        raise Exception("Username not found in user info")
    my_username = user_info.get("username")
    my_public_key = user_info.get("public_key")

    # Create the friend file and add my details if it doesn't exist
    try:
        with open(_get_friend_filepath(), 'w') as f:
            json.dump({my_username: my_public_key}, f, indent=4)
        return True
    except Exception as e:
        print(f"Error creating friend file: {e}")
        return False

def _load_friend_file() -> dict | None:
    try:
        with open(_get_friend_filepath(), 'r') as f:
            logger.debug(f"Loading friend file from {_get_friend_filepath()}")
            return json.load(f)
    except FileNotFoundError:
        logger.warning(f"Friend file not found at {_get_friend_filepath()}, creating a new one")
        if _create_friend_file():
            return _load_friend_file()
        return None
    except json.JSONDecodeError:
        logger.error(f"Error decoding JSON from friend file at {_get_friend_filepath()}")
        return None


def friend_in_friends(friend_username: str) -> bool:
    """Check if a friend exists in the friend file."""
    if not friend_file_exists():
        logger.error("Friend file does not exist")
        raise FileNotFoundError("Friend file does not exist")
    friend_data = _load_friend_file()
    return friend_username in friend_data
    
def save_friend(friend_username: str, public_key: str) -> bool:
    friend_data = _load_friend_file()
    if not friend_data:
        logger.error("Friend data is empty, cannot save friend")
        return False
    
    if friend_in_friends(friend_username):
        logger.info(f"Friend {friend_username} already exists, updating public key")
        
    friend_data[friend_username] = public_key

    with open(_get_friend_filepath(), 'w') as f:
        json.dump(friend_data, f, indent=4)
    return True

    

    