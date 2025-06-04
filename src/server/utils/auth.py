from datetime import datetime, UTC
from flask import jsonify, request
from server.utils.db_setup import get_session
from server.models.tables import OTPK, Users
from server.utils.jwt import generate_token, get_user_id_from_token, get_current_token, JWTError
from server.config import config
from typing import List, Dict
import logging
import nacl.pwhash
import base64

logger = logging.getLogger(__name__)

def login(username: str, password: str) -> dict:
    """Login route to authenticate users.

    Args:
        username (str): Username of the user.
        password (str): Password of the user.

    Returns:
        dict: A tuple containing (response_dict, status_code) where response_dict is either:
            - On success: {"access_token": str, "refresh_token": str}
            - On error: {"error": str} with additional fields for specific error cases
    """

    if not username or not password:
        logger.warning("Login failed: Missing required fields")
        return jsonify({"error": "Missing required fields"}), 400
    
    # Check the username and password against the database
    with get_session() as db:
        user: Users = db.query(Users).filter_by(username=username).first()

    # Cond 1: Username doesnt exist
    if not user:
        logger.warning(f"Login failed for user {username}: User not found")
        return jsonify({"error": "User not found"}), 404
    
    # Cond 2: Password is incorrect for the given 
    if not verify_password(user.password, password):
        logger.warning(f"Login failed for user {username}: Invalid password")
        return jsonify({"error": "Invalid password"}), 401

    # Check if SPK is too old
    current_time = datetime.now(UTC)
    if user.spk_updated_at.tzinfo is None:
        # If spk_updated_at is naive, make it timezone-aware
        user.spk_updated_at = user.spk_updated_at.replace(tzinfo=UTC)
    spk_age = current_time - user.spk_updated_at
    if spk_age > config.spk.max_age:
        logger.warning(f"Login failed for user {username}: SPK is too old (age: {spk_age.days} days)")
        return jsonify({
            "error": "SPK is too old",
            "spk_updated_at": user.spk_updated_at.isoformat(),
            "max_age_days": config.spk.max_age_days
        }), 403

    # Check if there are enough unused OTPKs
    user_info = {
        "user_id": user.id,
        "username": user.username
    }
    try:
        otpk_count = get_count_otpk(user_info)
        if otpk_count < config.otpk.min_unused_count:
            logger.warning(f"Login failed for user {username}: Not enough unused OTPKs (count: {otpk_count})")
            return jsonify({
                "error": "Not enough unused OTPKs",
                "current_count": otpk_count,
                "min_required": config.otpk.min_unused_count
            }), 403
    except ValueError as e:
        logger.warning(f"Login failed for user {username}: Error counting OTPKs - {str(e)}")
        return jsonify({"error": str(e)}), 400

    access_token, refresh_token = generate_token(user.id)
    logger.info(f"User {username} logged in successfully")
    return jsonify({
        "access_token": access_token,
        "refresh_token": refresh_token,
        "spk_updated_at": user.spk_updated_at.isoformat(),
        "unused_otpk_count": otpk_count
    }), 200

def sign_up(username: str, password: str, public_key: str, spk: str, spk_signature: str, salt: bytes) -> dict:
    """Sign up route to register new users.

    Args:
        username (str): Username of the new user.
        password (str): validated password of the new user.
        public_key (str): base64 encoded public key of the new user.
        spk (str): base64 encoded signed pre key of the new user.
        spk_signature (str): base64 encoded signature of the signed pre key.
        salt (bytes): salt used for hashing the password.

    Returns:
        dict: validated response containing access and refresh tokens or error message.
    """
    
    if not username or not password or not public_key or not spk or not spk_signature or not salt:
        logger.warning("Sign up failed: Missing required fields")
        return jsonify({"error": "Missing required fields"}), 400
    try:
        # Validate that the public key is a valid base64 string
        base64.b64decode(public_key)
        # Validate that the spk is a valid base64 string
        base64.b64decode(spk)
        # Validate that the spk_signature is a valid base64 string
        base64.b64decode(spk_signature)
    except Exception as e:
        logger.warning(f"Sign up failed for user {username}: Invalid base64 format - {str(e)}")
        return jsonify({"error": "Invalid base64 format for cryptographic data"}), 400
    
    with get_session() as db:
        # Cond 1: The username already exists
        existing_user = db.query(Users).filter_by(username=username).first()
        if existing_user:
            logger.warning(f"Sign up failed for user {username}: Username already exists")
            return jsonify({"error": "Username already exists"}), 409
        
        # Cond 2: The public key already exists -> should be unique
        existing_public_key = db.query(Users).filter_by(public_key=public_key).first()
        if existing_public_key:
            logger.warning(f"Sign up failed for user {username}: Public key already exists")
            return jsonify({"error": "Public key already exists"}), 409
        
        # Create a new user
        new_user = Users(
            username=username,
            password=hash_password(password),
            public_key=public_key,
            spk=spk,  # Store as base64 string
            spk_signature=spk_signature,  # Store as base64 string
            spk_updated_at=datetime.now(UTC),
            salt=salt,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC)
        )

        db.add(new_user)
        db.flush()  # Ensure new_user.id is available
        access_token, refresh_token = generate_token(new_user.id)
        db.commit()
    logger.info(f"User {username} signed up successfully")

    return jsonify({
        "access_token": access_token,
        "refresh_token": refresh_token
    }), 201

def change_password(token: str, new_password: str, salt: bytes) -> dict:
    """Change password route to update user password and salt.

    Args:
        token (str): valid, active JWT token.
        new_password (str): new password for the user.
        salt (bytes): new salt for the user (must be bytes).

    Returns:
        dict: response containing success message or error message.
    """
    
    if not token or not new_password or not salt:
        logger.warning("Change password failed: Missing required fields")
        return jsonify({"error": "Missing required fields"}), 400
    
    try:
        user_id = get_user_id_from_token(token)
    except JWTError as e:
        return jsonify({"error": e.message}), e.status

    with get_session() as db:
        user: Users = db.query(Users).filter_by(id=user_id).first()
        
        if not user:
            logger.warning(f"Change password failed for user {user_id}: User not found")
            return jsonify({"error": "User not found"}), 404
        
        # Cond 1: The new password is not provided
        if new_password == "" or new_password is None:
            logger.warning(f"Change password failed for user {user_id}: No new password provided")
            return jsonify({"error": "No new password provided"}), 400
        
        # Cond 2: The new password is the same as the current one
        if verify_password(user.password, new_password):
            logger.warning(f"Change password failed for user {user_id}: New password is the same as the current one")
            return jsonify({"error": "New password is the same as the current one"}), 400

        hashed_new_password = hash_password(new_password)
        user.password = hashed_new_password
        user.salt = salt
        user.updated_at = datetime.now(UTC)
        db.commit()
        logger.info(f"User {user_id} changed password and salt successfully")
    return jsonify({"message": "Password updated successfully"}), 200

def delete_account(username: str) -> dict:
    """Delete account route to remove a user from the database.

    Args:
        username (str): Username of the user to be deleted.

    Returns:
        dict: response containing success message or error message.
    """
    
    if not username:
        logger.warning("Delete account failed: Missing required fields")
        return jsonify({"error": "Missing required fields"}), 400
    
    with get_session() as db:
        user: Users = db.query(Users).filter_by(username=username).first()
        
        if not user:
            logger.warning(f"Delete account failed for user {username}: User not found")
            return jsonify({"error": "User not found"}), 404
        
        # Delete the user
        db.delete(user)
        db.commit()
    logger.info(f"User {username} deleted account successfully")
    return jsonify({"message": "Account deleted successfully"}), 200


def change_username(token: str, new_username: str) -> dict:
    """Change username route to update user information.

    Args:
        token (str): valid, active JWT token.
        new_username (str): new username for the user.

    Returns:
        dict: response containing success message or error message.
    """
    
    if not token or not new_username:
        logger.warning("Change username failed: Missing required fields")
        return jsonify({"error": "Missing required fields"}), 400
    
    try:
        user_id = get_user_id_from_token(token)
    except JWTError as e:
        return jsonify({"error": e.message}), e.status

    with get_session() as db:
        user: Users = db.query(Users).filter_by(id=user_id).first()
        if not user:
            logger.warning(f"Change username failed for user {user_id}: User not found")      
            return jsonify({"error": "User not found"}), 404
        
        # Cond 1: The new username already exists
        existing_user = db.query(Users).filter_by(username=new_username).first()
        if existing_user:
            logger.warning(f"Change username failed for user {user_id}: Username already exists")
            return jsonify({"error": "Username already exists"}), 409
        
        # Cond 2: Username is the same as the current one
        if user.username == new_username:
            logger.warning(f"Change username failed for user {user_id}: New username is the same as the current one")
            return jsonify({"error": "New username is the same as the current one"}), 400
        
        # Update the username
        user.username = new_username
        user.updated_at = datetime.now(UTC)
        db.commit()
    logger.info(f"User {user_id} changed username successfully")

    return jsonify({"message": "Username updated successfully"}), 200

def get_current_user() -> dict:
    """Get the current user from the JWT token.

    Args:
        token (str): valid, active JWT token.

    Returns:
        tuple: (user_info, status_code) where user_info is a dictionary containing:
            - user_id: The user's ID
            - username: The user's username
            - public_key: The user's public key
            - salt: The user's salt
            - created_at: Account creation timestamp
            - updated_at: Last update timestamp
    """
    user_id = None
    try:
        current_token = get_current_token()
        user_id = get_user_id_from_token(current_token)
    except JWTError as e:
        return {"error": str(e)}, e.status
    with get_session() as db:
        user: Users = db.query(Users).filter_by(id=user_id).first()

    if not user:
        logger.warning(f"Current user retrieval failed: User not found for token")
        return jsonify({"error": "User not found"}), 404

    user_info = {
        "user_id": user.id,
        "username": user.username,
        "public_key": user.public_key,
        "salt": base64.b64encode(user.salt).decode() if isinstance(user.salt, bytes) else user.salt,
        "created_at": user.created_at,
        "updated_at": user.updated_at
    }
    return user_info, 200

def get_public_key(username: str) -> dict:
    """Get public key route to retrieve the user's public key.

    Args:
        username (str): Username of the user whose public key is requested.

    Returns:
        dict: response containing the public key or error message.
    """
    
    if not username:
        logger.warning("Get public key failed: Missing required fields")
        return jsonify({"error": "Missing required fields"}), 400
    
    with get_session() as db:
        user: Users = db.query(Users).filter_by(username=username).first()
        
    if not user:
        logger.warning(f"Get public key failed for user {username}: User not found")
        return jsonify({"error": "User not found"}), 404
    
    return jsonify({"public_key": user.public_key}), 200

def hash_password(password: str) -> bytes:
    """Hash the password with the provided salt.

    Args:
        password (str): The password to hash.
        salt (bytes): The salt to use for hashing.

    Returns:
        bytes: The hashed password.
    """

    if not password:
        raise ValueError("Password must be provided")
    
    return nacl.pwhash.str(password.encode(), opslimit=nacl.pwhash.OPSLIMIT_SENSITIVE, memlimit=nacl.pwhash.MEMLIMIT_SENSITIVE)

def verify_password(hashed_password: bytes, password: str) -> bool:
    """Verify the password against the hashed password.

    Args:
        hashed_password (bytes): The hashed password to verify against.
        password (str): The password to verify.

    Returns:
        bool: True if the password matches, False otherwise.
    """
    
    if not hashed_password or not password:
        raise ValueError("Hashed password and password must be provided")
    
    try:
        return nacl.pwhash.verify(hashed_password, password.encode())
    except nacl.exceptions.InvalidkeyError:
        return False
    
def get_count_otpk(user_info : dict) -> int:
    """Count the number of unused one-time pre keys (OTPK) for the current user.

    Returns:
        int: The count of unused OTPKs for the user.
    """
    user_id = user_info.get("user_id")
    username = user_info.get("username")
    if not user_id:
        logger.warning("Count OTPK failed: Missing required fields")
        raise ValueError("Missing required fields: user_id")

    with get_session() as db:
        # Count only unused OTPKs (where used = 0) - database count is most efficient
        otpk_count = db.query(OTPK).filter_by(user_id=user_id, used=0).count()
        logger.info(f"Counted {otpk_count} unused OTPKs for user {username})")
    return otpk_count

def add_otpks(otpks: List[str], user_info: Dict) -> Dict:
    """Add one-time pre keys (OTPKs) for the current user.

    Args:
        otpks (List[str]): List of base64 encoded one-time pre keys to add.
        user_info (Dict): Dictionary containing user information.

    Returns:
        Dict: Response containing success message and otpk count.
    """
    
    if not otpks or not user_info:
        logger.warning("Add OTPKs failed: Missing required fields")
        return {"error": "Missing required fields"}, 400
    
    user_id = user_info.get("user_id")
    if not user_id:
        logger.warning("Add OTPKs failed: Missing user_id in user_info")
        return {"error": "Missing user_id in user_info"}, 400

    # Validate base64 format for all OTPKs
    for otpk in otpks:
        try:
            base64.b64decode(otpk)
        except Exception as e:
            logger.warning(f"Add OTPKs failed: Invalid base64 format for OTPK: {str(e)}")
            return {"error": "Invalid base64 format for OTPK"}, 400

    with get_session() as db:
        # Add all new OTPKs
        for otpk in otpks:            
            new_otk = OTPK(
                user_id=user_id,
                key=otpk,
                used=0,  # Initially unused
                created_at=datetime.now(UTC),
                updated_at=datetime.now(UTC)
            )
            db.add(new_otk)
        
        # Flush to make new records visible to queries
        db.flush()
        
        # Get count using existing function
        try:
            otpk_count = get_count_otpk(user_info)
        except ValueError as e:
            logger.warning(f"Add OTPKs failed: Error counting OTPKs - {str(e)}")
            return {"error": str(e)}, 400
        
        # Commit the transaction
        db.commit()
    
    logger.info(f"Added {len(otpks)} OTPKs for user {user_info['username']}")
    return {
        "message": f"Added {len(otpks)} OTPKs successfully",
        "otpk_count": otpk_count
    }, 201

def retrieve_key_bundle(username: str) -> Dict:
    """Get key bundle for a selected user.

    Args:
        username (str): Username of the user whose key bundle is requested.

    Returns:
        Dict: Response containing the key bundle (OTPK, SPK, SPK signature, updated timestamp) or error message.
    """
    
    if not username:
        logger.warning("Get key bundle failed: Missing required fields")
        return {"error": "Missing required fields"}, 400
    
    with get_session() as db:
        user: Users = db.query(Users).filter_by(username=username).first()
        
        if not user:
            logger.warning(f"Get key bundle failed for user {username}: User not found")
            return {"error": "User not found"}, 404
            
        # Get the first unused OTPK for the user
        otpk = db.query(OTPK).filter_by(user_id=user.id, used=0).first()
        if not otpk:
            logger.warning(f"Get key bundle failed for user {username}: No unused OTPK found")
            return {"error": "No unused OTPK found"}, 404
            
        # Store all needed values before closing the session
        otpk_key = otpk.key
        spk = user.spk
        spk_signature = user.spk_signature
        spk_updated_at = user.spk_updated_at.isoformat()
        
        # Mark the OTPK as used
        otpk.used = 1
        otpk.updated_at = datetime.now(UTC)
        db.commit()
        
    logger.info(f"Retrieved key bundle for user {username}")
    return {
        "otpk": otpk_key,
        "spk": spk,
        "spk_signature": spk_signature,
        "updatedAt": spk_updated_at
    }, 200

def update_spk(user_info: Dict, spk: str, spk_signature: str) -> Dict:
    """Update the signed pre key (SPK) for a user.

    Args:
        user_info (Dict): Dictionary containing user information.
        spk (str): Base64 encoded signed pre key.
        spk_signature (str): Base64 encoded signature of the signed pre key.

    Returns:
        Dict: Response containing success message or error message.
    """
    
    if not user_info or not spk or not spk_signature:
        logger.warning("Update SPK failed: Missing required fields")
        return {"error": "Missing required fields"}, 400
    
    user_id = user_info.get("user_id")
    if not user_id:
        logger.warning("Update SPK failed: Missing user_id in user_info")
        return {"error": "Missing user_id in user_info"}, 400

    try:
        # Validate base64 format
        base64.b64decode(spk)
        base64.b64decode(spk_signature)
    except Exception as e:
        logger.warning(f"Update SPK failed: Invalid base64 format - {str(e)}")
        return {"error": "Invalid base64 format for cryptographic data"}, 400

    with get_session() as db:
        user: Users = db.query(Users).filter_by(id=user_id).first()
        if not user:
            logger.warning(f"Update SPK failed for user {user_id}: User not found")
            return {"error": "User not found"}, 404
        
        # Update the SPK and signature
        user.spk = spk
        user.spk_signature = spk_signature
        user.spk_updated_at = datetime.now(UTC)
        user.updated_at = datetime.now(UTC)
        db.commit()
    
    logger.info(f"Updated SPK for user {user_info['username']}")
    return {"message": "Signed Pre Key updated successfully"}, 200