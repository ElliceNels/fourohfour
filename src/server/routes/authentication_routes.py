from flask import Blueprint, jsonify, request
from server.utils import auth, jwt

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
        "access_token": "<JWT_access_token>",
        "refresh_token": "<JWT_refresh_token>"
    }
    """

    data = request.get_json()
    username = data.get('username')
    hash_password = data.get('hashed_password')

    return auth.login(username, hash_password)

@authentication_routes.route('/refresh', methods=['POST'])
def refresh():
    """Refresh access token using refresh token.
    
    Expected JSON payload:
    {
        "refresh_token": "<JWT_refresh_token>"
    }

    Expected response:
    {
        "access_token": "<new_JWT_access_token>"
    }
    """
    data = request.get_json()
    refresh_token = data.get('refresh_token')
    
    if not refresh_token:
        return jsonify({"error": "Missing refresh token"}), 400
        
    new_access_token, error = jwt.refresh_access_token(refresh_token)
    if error:
        return error
        
    return jsonify({"access_token": new_access_token}), 200

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

    return auth.sign_up(username, hash_password, public_key, salt)

@authentication_routes.route('/logout', methods=['POST'])
def logout():
    """Logout route to invalidate the user session.
    
    Expected headers:
    Authorization: Bearer <access_token>
    X-Refresh-Token: <refresh_token>

    Expected response:
    {
        "message": "Logged out successfully"
    }
    """

    # Get access token from Authorization header
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({"error": "Missing or malformed access token"}), 401
    access_token = auth_header.split(' ')[1]

    # Get refresh token from custom header
    refresh_token = request.headers.get('X-Refresh-Token')
    if not refresh_token:
        return jsonify({"error": "Missing refresh token"}), 400
        
    # Invalidate both tokens
    if jwt.invalidate_token(access_token) and jwt.invalidate_token(refresh_token):
        return jsonify({"message": "Logged out successfully"}), 200
    else:
        return jsonify({"error": "Failed to invalidate tokens"}), 500

@authentication_routes.route('/change_password', methods=['POST'])
def change_password():
    """Change password route to update user password.
    
    Expected JSON payload:
    {
        "new_password": "<new_password>"
    }
    Expected response:
    {
        "message": "Password updated successfully"
    }
    """
    
    data = request.get_json()
    new_password = data.get('new_password')

    # Extract the JWT token from the request headers
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        token = auth_header.split(' ')[1]
        return auth.change_password(token, new_password)
    else:
        return jsonify({"error": "Missing or malformed token"}), 401

@authentication_routes.route('/delete_account', methods=['POST'])
def delete_account():
    """Delete account route to remove user account.
    Expected JSON payload:
    {
        "username": "<username>"
    }

    Expected response:
    {
        "message": "Account deleted successfully"
    }
    """

    data = request.get_json()
    username = data.get('username')

    # Extract the JWT token from the request headers
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '): # TODO: Check if the token is valid
        return auth.delete_account(username)
    else:
        return jsonify({"error": "Missing or malformed token"}), 401

@authentication_routes.route('/change_username', methods=['POST'])
def change_username():
    """Update profile route to modify user information.
    Expected JSON payload:
    {
        "new_username": "<new_username>"
    }
    Expected response:
    {
        "message": "Username updated successfully"
    }
    """
    
    data = request.get_json()
    new_username = data.get('new_username')

    # Extract the JWT token from the request headers
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '): # TODO: Check if the token is valid
        token = auth_header.split(' ')[1]
        return auth.change_username(token, new_username)
    else:
        return jsonify({"error": "Missing or malformed token"}), 401

@authentication_routes.route('/get_current_user', methods=['GET'])
def get_current_user():
    """Get user info route to retrieve current user information.
    
    Expected response:
    {
        "username": "<username>",
        "password": "<hashed_password>",
        "public_key": "<public_key>",
        "salt": "<salt>",
        "created_at": "<created_at>",
        "updated_at": "<updated_at>"
    }
    """
    user_info, status_code = auth.get_current_user()
    if status_code != 200:
        return user_info, status_code
    return jsonify(user_info), 200

