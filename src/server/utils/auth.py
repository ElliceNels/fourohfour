from datetime import datetime
from flask import jsonify, request
from src.server.utils.db_setup import get_session
from src.server.models.tables import Users
from server.utils.jwt import generate_token, get_user_id_from_token, get_current_token


def login(username: str, hash_password: bytes) -> dict:
    """Login route to authenticate users.

    Args:
        username (str): Username of the user.
        hash_password (bytes): Hashed password of the user.

    Returns:
        dict: response containing access and refresh tokens or error message.
    """

    if not username or not hash_password:
        return jsonify({"error": "Missing required fields"}), 400
    
    # Check the username and password against the database
    db = get_session()
    user: Users = db.query(Users).filter_by(username=username).first()
    db.close()

    # Cond 1: Username doesnt exist
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    # Cond 2: Password is incorrect for the given username
    if user.password != hash_password:
        return jsonify({"error": "Invalid password"}), 401

    access_token, refresh_token = generate_token(user.id)
    return jsonify({
        "access_token": access_token,
        "refresh_token": refresh_token
    }), 200

def sign_up(username: str, password: str, public_key: bytes, salt: bytes) -> dict:
    """Sign up route to register new users.

    Args:
        username (str): Username of the new user.
        password (str): validated password of the new user.
        public_key (bytes): public key of the new user.
        salt (bytes): salt used for hashing the password.

    Returns:
        dict: validated response containing access and refresh tokens or error message.
    """
    
    if not username or not password or not public_key or not salt:
        return jsonify({"error": "Missing required fields"}), 400
    
    db = get_session()

    # Cond 1: The username already exists
    existing_user = db.query(Users).filter_by(username=username).first()
    if existing_user:
        db.close()
        return jsonify({"error": "Username already exists"}), 409
    
    # Cond 2: The public key already exists -> should be unique
    existing_public_key = db.query(Users).filter_by(public_key=public_key).first()
    if existing_public_key:
        db.close()
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
    db.commit()
    db.close()

    access_token, refresh_token = generate_token(new_user.id)
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
        return jsonify({"error": "Missing required fields"}), 400
    
    user_id, error = get_user_id_from_token(token)
    if error:
        return error

    db = get_session()
    user: Users = db.query(Users).filter_by(id=user_id).first()
    
    if not user:
        db.close()
        return jsonify({"error": "User not found"}), 404
    
    # Cond 1: The new password is the same as the current one
    if user.password == new_password:
        db.close()
        return jsonify({"error": "New password is the same as the current one"}), 400
    
    # Update the password
    user.password = new_password
    user.updated_at = datetime.now()
    db.commit()
    db.close()
    return jsonify({"message": "Password updated successfully"}), 200

def delete_account(username: str) -> dict:
    """Delete account route to remove a user from the database.

    Args:
        username (str): Username of the user to be deleted.

    Returns:
        dict: response containing success message or error message.
    """
    
    if not username:
        return jsonify({"error": "Missing required fields"}), 400
    
    db = get_session()
    user: Users = db.query(Users).filter_by(username=username).first()
    
    if not user:
        db.close()
        return jsonify({"error": "User not found"}), 404
    
    # Delete the user
    db.delete(user)
    db.commit()
    db.close()
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
        return jsonify({"error": "Missing required fields"}), 400
    
    user_id, error = get_user_id_from_token(token)
    if error:
        return error

    db = get_session()
    user: Users = db.query(Users).filter_by(id=user_id).first()
    if not user:
        db.close()
        return jsonify({"error": "User not found"}), 404
    
    # Cond 1: The new username already exists
    existing_user = db.query(Users).filter_by(username=new_username).first()
    if existing_user:
        db.close()
        return jsonify({"error": "Username already exists"}), 409
    
    # Cond 2: Username is the same as the current one
    if user.username == new_username:
        db.close()
        return jsonify({"error": "New username is the same as the current one"}), 400
    
    # Update the username
    user.username = new_username
    user.updated_at = datetime.now()
    db.commit()
    db.close()
    return jsonify({"message": "Username updated successfully"}), 200

def get_current_user(token: str) -> dict:
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
    token, error = get_current_token()
    if error:
        return error['response'], error['status']

    user_id, error = get_user_id_from_token(token)
    if error:
        return error['response'], error['status']

    db = get_session()
    user: Users = db.query(Users).filter_by(id=user_id).first()
    db.close()

    if not user:
        return jsonify({"error": "User not found"}), 404

    user_info = {
        "user_id": user.user_id,
        "username": user.username,
        "password": user.password,
        "public_key": user.public_key,
        "salt": user.salt,
        "created_at": user.created_at,
        "updated_at": user.updated_at
    }
    return user_info, 200
