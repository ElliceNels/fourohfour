from flask import Blueprint, jsonify, request
from server.utils import auth, jwt
from server.utils.jwt import JWTError
import logging

logger = logging.getLogger(__name__)

authentication_routes = Blueprint('authentication_routes', __name__)

@authentication_routes.route('/login', methods=['POST'])
def login():
    """Login route to authenticate users.
    
    Expected JSON payload:
    {
        "username": "<username>",
        "password": "<password>",
    }

    Expected response:
    {
        "access_token": "<JWT_access_token>",
        "refresh_token": "<JWT_refresh_token>"
    }
    """

    data = request.get_json()
    logger.debug(f"Received login request for username: {data.get('username')}")
    username = data.get('username')
    password = data.get('password')

    return auth.login(username, password)

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
        
    try:
        new_access_token = jwt.refresh_access_token(refresh_token)
        return jsonify({"access_token": new_access_token}), 200
    except JWTError as e:
        return jsonify({"error": e.message}), e.status

@authentication_routes.route('/sign_up', methods=['POST'])
def sign_up():
    """Sign up route to register new users.
    
    Expected JSON payload:
    {
        "username": "<username>",
        "password": "<password>",
        "public_key": "<public_key>",
        "salt": "<salt>"
    }

    Expected response:
    {
        "token": <JWT_token>
    }
    """
    
    data = request.get_json()
    logger.debug(f"Received sign up request")
    username = data.get('username')
    password = data.get('password')
    public_key = data.get('public_key')
    salt = data.get('salt')
    bytes_salt = salt.encode('utf-8') if isinstance(salt, str) else salt

    return auth.sign_up(username, password, public_key, bytes_salt)

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

    # Get refresh token from custom header
    refresh_token = request.headers.get('X-Refresh-Token')
    if not refresh_token:
        logger.warning("Logout failed: Missing or malformed refresh token")
        return jsonify({"error": "Missing refresh token"}), 400
        
    try:
        access_token = jwt.get_current_token()
    except JWTError as e:
        logger.warning("Logout failed: Missing or malformed access token")
        return jsonify({"error": e.message}), e.status

    # Invalidate both tokens
    if jwt.invalidate_token(access_token) and jwt.invalidate_token(refresh_token):
        logger.info(f"User logged out successfully with token")
        return jsonify({"message": "Logged out successfully"}), 200
    else:
        logger.warning("Logout failed: Failed to invalidate tokens")
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
    logger.debug(f"Received change password request")
    new_password = data.get('new_password')

    try:
        token = jwt.get_current_token()
    except JWTError as e:
        logger.warning("Change password failed: Missing or malformed token")
        return jsonify({"error": e.message}), e.status

    return auth.change_password(token, new_password)

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
    logger.debug(f"Received delete account request with data: {data}")
    username = data.get('username')

    try:
        token = jwt.get_current_token()
    except JWTError as e:
        logger.warning("Delete account failed: Missing or malformed token")
        return jsonify({"error": e.message}), e.status

    return auth.delete_account(username)

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
    logger.debug(f"Received change username request")
    new_username = data.get('new_username')

    try:
        token = jwt.get_current_token()
    except JWTError as e:
        logger.warning("Change username failed: Missing or malformed token")
        return jsonify({"error": e.message}), e.status

    return auth.change_username(token, new_username)

@authentication_routes.route('/get_current_user', methods=['GET'])
def get_current_user():
    """Get user info route to retrieve current user information.
    
    Expected response:
    {
        "username": "<username>",
        "public_key": "<public_key>",
        "salt": "<salt>",
        "created_at": "<created_at>",
        "updated_at": "<updated_at>"
    }
    """
    logger.debug("Received request to get current user")
    try:
        user_info, status_code = auth.get_current_user()
        if status_code != 200:
            logger.warning("Get current user failed: Missing or malformed token")
            return user_info, status_code
        return jsonify(user_info), 200
    except JWTError as e:
        return jsonify({"error": e.message}), e.status



@authentication_routes.route('/get_public_key', methods=['GET'])
def get_public_key():
    """Get public key route to retrieve the user's public key.

    Expected query parameter:
        /get_public_key?username=<username>
    
    Expected response:
    {
        "public_key": "<public_key>"
    }
    """
    logger.debug("Received request to get public key")

    username = request.args.get('username')
    if not username:
        logger.warning("Get public key failed: Missing username")
        return jsonify({"error": "Missing username"}), 400

    try:
        return auth.get_public_key(username=username) 
    except Exception as e:
        return jsonify({"error": str(e)}), 500

