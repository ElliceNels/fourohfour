from datetime import datetime
from flask import jsonify
from src.server.app import Session
from src.server.models.tables import Users


def login(username: str, hash_password: bytes) -> dict:
    """Login route to authenticate users.

    Args:
        username (str): Username of the user.
        hash_password (bytes): Hashed password of the user.

    Returns:
        dict: response containing JWT token or error message.
    """

    if not username or not hash_password:
        return jsonify({"error": "Missing required fields"}), 400
    
    # Check the username and password against the database
    db = Session()
    user: Users = db.query(Users).filter_by(username=username).first()
    db.close()

    # Cond 1: Username doesnt exist
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    # Cond 2: Password is incorrect for the given username
    if user.password != hash_password:
        return jsonify({"error": "Invalid password"}), 401

    token = -1 # TODO: Replace with actual JWT token generation logic
    return jsonify({"token": token}), 200

def sign_up(username: str, password: str, public_key: bytes, salt: bytes) -> dict:
    """Sign up route to register new users.

    Args:
        username (str): Username of the new user.
        password (str): validated password of the new user.
        public_key (bytes): public key of the new user.
        salt (bytes): salt used for hashing the password.

    Returns:
        dict: validated response containing JWT token or error message.
    """
    
    if not username or not password or not public_key or not salt:
        return jsonify({"error": "Missing required fields"}), 400
    
    db = Session()

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

    token = -1 # TODO: Replace with actual JWT token generation logic
    return jsonify({"token": token}), 201


def current_user(token: str) -> dict:
    """Get the current user from the JWT token.

    Args:
        token (str): valid, active JWT token.

    Returns:
        dict: response containing user information or error message.
    """
    
    user_id = -1 # TODO: Replace with actual JWT token decoding logic

    db = Session()
    user: Users = db.query(Users).filter_by(id=user_id).first()
    db.close()

    if not user:
        return jsonify({"error": "User not found"}), 404
    
    user_info = {
        "username": user.username,
        "public_key": user.public_key,
        "created_at": user.created_at,
        "updated_at": user.updated_at
    }
    return jsonify(user_info), 200