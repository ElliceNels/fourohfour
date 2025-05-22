from flask import Blueprint, jsonify, request
from server.utils import auth_utils

authentication_routes = Blueprint('authentication_routes', __name__)

@authentication_routes.route('/login', methods=['POST'])
def login():
    """Login route to authenticate users.
    
    Expected JSON payload:
    {
        "username": "<username>",
        "hashed_password": "<hashed_password>",
    }

    Expected response:
    {
        "token": <JWT_token>
    }
    """

    data = request.get_json()
    username = data.get('username')
    hash_password = data.get('hashed_password')

    return auth_utils.login(username, hash_password)

@authentication_routes.route('/sign_up', methods=['POST'])
def sign_up():
    """Sign up route to register new users.
    
    Expected JSON payload:
    {
        "username": "<username>",
        "hashed_password": "<hashed_password>",
        "public_key": "<public_key>",
        "salt": "<salt>"
    }

    Expected response:
    {
        "token": <JWT_token>
    }
    """
    
    data = request.get_json()
    username = data.get('username')
    hash_password = data.get('hashed_password')
    public_key = data.get('public_key')
    salt = data.get('salt')

    return auth_utils.sign_up(username, hash_password, public_key, salt)

@authentication_routes.route('/logout', methods=['POST'])
def logout():
    """Logout route to invalidate the user session."""
    # This route should handle user logout and invalidate the JWT token
    ...

@authentication_routes.route('/change_password', methods=['POST'])
def change_password():
    """Change password route to update user password."""
    # This route should handle password change and return a success message
    ...

@authentication_routes.route('/delete_account', methods=['POST'])
def delete_account():
    """Delete account route to remove user account."""
    # This route should handle account deletion and return a success message
    ...

@authentication_routes.route('/update_profile', methods=['POST'])
def update_profile():
    """Update profile route to modify user information."""
    # This route should handle profile updates and return a success message
    ...

@authentication_routes.route('/get_current_user', methods=['GET'])
def get_current_user():
    """Get user info route to retrieve current user information.
    
    Expected response:
    {
        "username": "<username>",
        "public_key": "<public_key>",
        "created_at": "<created_at>",
        "updated_at": "<updated_at>"
    }
    """

    # Extract the JWT token from the request headers
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '): # TODO: Check if the token is valid
        token = auth_header.split(' ')[1]
        return auth_utils.current_user(token)
    else:
        return jsonify({"error": "Missing or malformed token"}), 401
