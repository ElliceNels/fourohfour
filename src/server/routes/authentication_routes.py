from flask import Blueprint, jsonify, request
from server.utils import auth, jwt
from server.utils.jwt import JWTError
import logging
import base64

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
        "spk": "<signed_pre_key>",
        "spk_signature": "<spk_signature>",
        "salt": "<salt>"
    }

    Expected response:
    {
        "access_token": "<JWT_access_token>",
        "refresh_token": "<JWT_refresh_token>"
    }
    """
    
    data = request.get_json()
    logger.debug(f"Received sign up request")
    username = data.get('username')
    password = data.get('password')
    public_key = data.get('public_key')
    spk = data.get('spk')
    spk_signature = data.get('spk_signature')
    salt = data.get('salt')

    # Validate base64 format for cryptographic data
    try:
        if public_key:
            base64.b64decode(public_key)
        if spk:
            base64.b64decode(spk)
        if spk_signature:
            base64.b64decode(spk_signature)
    except Exception as e:
        logger.warning(f"Sign up failed: Invalid base64 format for cryptographic data - {str(e)}")
        return jsonify({"error": "Invalid base64 format for cryptographic data"}), 400

    try:
        # First try to decode as base64 if it's a string
        if isinstance(salt, str):
            bytes_salt = base64.b64decode(salt)
        else:
            bytes_salt = salt
    except Exception as e:
        logger.warning(f"Sign up failed: Invalid salt format - {str(e)}")
        return jsonify({"error": "Invalid salt format"}), 400

    return auth.sign_up(username, password, public_key, spk, spk_signature, bytes_salt)

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
        "new_password": "<new_password>",
        "salt": "<salt>"
    }
    Expected response:
    {
        "message": "Password updated successfully"
    }
    """
    
    data = request.get_json()
    logger.debug(f"Received change password request")
    new_password = data.get('new_password')
    salt = data.get('salt')
    try:
        # First try to decode as base64 if it's a string
        if isinstance(salt, str):
            bytes_salt = base64.b64decode(salt)
        else:
            bytes_salt = salt
    except Exception as e:
        logger.warning(f"Change password failed: Invalid salt format - {str(e)}")
        return jsonify({"error": "Invalid salt format"}), 400

    try:
        token = jwt.get_current_token()
    except JWTError as e:
        logger.warning("Change password failed: Missing or malformed token")
        return jsonify({"error": e.message}), e.status

    return auth.change_password(token, new_password, bytes_salt)

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
            return jsonify({"error": "Missing or malformed token"}), status_code
        return jsonify({
            "username": user_info["username"],
            "public_key": user_info["public_key"],
            "salt": user_info["salt"],
            "created_at": user_info["created_at"],
            "updated_at": user_info["updated_at"]
        }), status_code
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

@authentication_routes.route('/count_otpk', methods=['GET'])
def count_otpk():
    """Count OTPK route to retrieve the count of one-time pre keys for the current user.

    Expected response:
    {
        "otpk_count": <number_of_otpk>
    }
    """
    logger.debug("Received request to count OTPKs")
    try:
        user_info, status_code = auth.get_current_user()
        if status_code != 200:
            return jsonify({"error": "Failed to get current user"}), status_code
        
        otpk_count = auth.get_count_otpk(user_info)
        return jsonify({"otpk_count": otpk_count}), 200
    except JWTError as e:
        return jsonify({"error": e.message}), e.status
    except ValueError as e:
        logger.warning(f"Count OTKs failed: {str(e)}")
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
@authentication_routes.route('/add_otpks', methods=['POST'])
def add_otpks():
    """Add OTPK route to generate and add one-time pre keys for the current user.

    Expected JSON payload:
    {
     otpks:
        [
            dGhpcyBpcyBhIHRlc3Qga2V5IDMzNTU1Mw==, YW5vdGhlciB0ZXN0IGtleSAyMzQ1Njc4OQ== #base 64 encoded!
        ]
    }

    Expected response:
    {
        "message": "OTPKs added successfully",
        "otpk_count": <new_otpk_count>
    }
    """
    try:
        data = request.get_json()
        otpks = data.get('otpks')
        if not data or not otpks:
            logger.warning("Add OTPKs failed: Missing or malformed request data")
            return jsonify({"error": "Missing request fields"}), 400

        # Validate base64 format for all OTPKs
        try:
            for otpk in otpks:
                base64.b64decode(otpk)
        except Exception as e:
            logger.warning(f"Add OTPKs failed: Invalid base64 format for OTPK - {str(e)}")
            return jsonify({"error": "Invalid base64 format for OTPK"}), 400
        
        user_info, status_code = auth.get_current_user()
        if status_code != 200:
            return jsonify({"error": "Failed to get current user"}), status_code
            
        return auth.add_otpks(otpks, user_info)
    except Exception as e:
        logger.error(f"Error adding OTPKs: {str(e)}")
        return jsonify({"error": str(e)}), 500
    
@authentication_routes.route('/retrieve_key_bundle', methods=['GET'])
def retrieve_key_bundle():
    """Get OTPK route to retrieve a one-time pre key for a selected user.
        Expected JSON payload:
    {
        "username": "<username>"
    }
    Expected response:
    {
        "otpk": "<base64_encoded_otpk>"
        "spk": "<base64_encoded_spk>"
        "spk_signature": "<base64_encoded_spk_signature>"
        "updatedAt": "<updated_at>"
    }
    """
    logger.debug("Received request to get OTPK")
    username = request.args.get('username')
    if not username:
        logger.warning("Get OTPK failed: Missing username")
        return jsonify({"error": "Missing username"}), 400
    try:
        response, status_code = auth.retrieve_key_bundle(username)
        if status_code != 200:
            return jsonify(response), status_code
        return jsonify(response), 200
    except Exception as e:
        logger.error(f"Error retrieving key bundle: {str(e)}")
        return jsonify({"error": str(e)}), 500

@authentication_routes.route('/update_spk', methods=['POST'])
def update_spk():
    """Update Signed Pre Key route to update the signed pre key for the current user.	
    Expected JSON payload:
    {
        "spk": "<signed_pre_key>",
        "spk_signature": "<spk_signature>"
    }
    Expected response:
    {
        "message": "Signed Pre Key updated successfully"
    }
    """
    logger.debug("Received request to update signed pre key")
    
    try:
        # Get current user info
        user_info, status_code = auth.get_current_user()
        if status_code != 200:
            return jsonify({"error": "Failed to get current user"}), status_code

        # Get SPK data from request
        data = request.get_json()
        if not data or 'spk' not in data or 'spk_signature' not in data:
            logger.warning("Update SPK failed: Missing required fields")
            return jsonify({"error": "Missing required fields"}), 400

        spk = data['spk']
        spk_signature = data['spk_signature']

        # Validate base64 format
        try:
            base64.b64decode(spk)
            base64.b64decode(spk_signature)
        except Exception as e:
            logger.warning(f"Update SPK failed: Invalid base64 format - {str(e)}")
            return jsonify({"error": "Invalid base64 format for cryptographic data"}), 400

        # Call auth function to update SPK
        response, status_code = auth.update_spk(user_info, spk, spk_signature)
        return jsonify(response), status_code

    except Exception as e:
        logger.error(f"Error updating signed pre key: {str(e)}")
        return jsonify({"error": str(e)}), 500