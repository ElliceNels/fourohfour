from datetime import datetime
from flask import jsonify, request
from server.utils.db_setup import get_session
from server.models.tables import Users
from server.utils.jwt import generate_token, get_user_id_from_token, get_current_token, JWTError
import logging
import base64

logger = logging.getLogger(__name__)

def login(username: str, hash_password: bytes) -> dict:
    """Login route to authenticate users.

    Args:
        username (str): Username of the user.
        hash_password (bytes): Hashed password of the user.

    Returns:
        dict: response containing access and refresh tokens or error message.
    """

    if not username or not hash_password:
        logger.warning("Login failed: Missing required fields")
        return jsonify({"error": "Missing required fields"}), 400
    
    # Check the username and password against the database
    with get_session() as db:
        user: Users = db.query(Users).filter_by(username=username).first()

    # Cond 1: Username doesnt exist
    if not user:
        logger.warning(f"Login failed for user {username}: User not found")
        return jsonify({"error": "User not found"}), 404
    
    # Cond 2: Password is incorrect for the given username
    if user.password != hash_password:
        logger.warning(f"Login failed for user {username}: Invalid password")
        return jsonify({"error": "Invalid password"}), 401

    access_token, refresh_token = generate_token(user.id)
    logger.info(f"User {username} logged in successfully")
    return jsonify({
        "access_token": access_token,
        "refresh_token": refresh_token
    }), 200

def sign_up(username: str, password: str, public_key: str, salt: bytes) -> dict:
    """Sign up route to register new users.

    Args:
        username (str): Username of the new user.
        password (str): validated password of the new user.
        public_key (str): base64 encoded public key of the new user.
        salt (bytes): salt used for hashing the password.

    Returns:
        dict: validated response containing access and refresh tokens or error message.
    """
    
    if not username or not password or not public_key or not salt:
        logger.warning("Sign up failed: Missing required fields")
        return jsonify({"error": "Missing required fields"}), 400
    
    try:
        # Validate that the public key is a valid base64 string
        base64.b64decode(public_key)
    except Exception as e:
        logger.warning(f"Sign up failed for user {username}: Invalid public key format - {str(e)}")
        return jsonify({"error": "Invalid public key format - must be base64 encoded"}), 400
    
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
            password=password,
            public_key=public_key,
            salt=salt,
            created_at=datetime.now(),
            updated_at=datetime.now()
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

def change_password(token: str, new_password: str) -> dict:
    """Change password route to update user password.

    Args:
        token (str): valid, active JWT token.
        new_password (str): new password for the user.

    Returns:
        dict: response containing success message or error message.
    """
    
    if not token or not new_password:
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
        
        # Cond 1: The new password is the same as the current one
        if user.password == new_password:
            logger.warning(f"Change password failed for user {user_id}: New password is the same as the current one")
            return jsonify({"error": "New password is the same as the current one"}), 400
        
        # Cond 2: The new password is not provided
        if new_password == "" or new_password is None:
            logger.warning(f"Change password failed for user {user_id}: No new password provided")
            return jsonify({"error": "No new password provided"}), 400

        # Update the password
        user.password = new_password
        user.updated_at = datetime.now()
        db.commit()
        logger.info(f"User {user_id} changed password successfully")
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
        user.updated_at = datetime.now()
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
            - password: The user's hashed password
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
        "password": user.password,
        "public_key": user.public_key,
        "salt": user.salt,
        "created_at": user.created_at,
        "updated_at": user.updated_at
    }
    return user_info, 200
