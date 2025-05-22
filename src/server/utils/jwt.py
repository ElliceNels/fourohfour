from datetime import datetime, UTC
import jwt
from flask import jsonify, current_app, request
from server.app import Session
from server.models.tables import TokenBlacklist
from server.config import config

def get_current_token() -> tuple[str | None, dict | None]:
    """Extract and validate the JWT token from the Authorization header.
    
    Returns:
        tuple: (token, error_message) where either token or error_message will be None
    """
    try:
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return None, jsonify({"error": "Missing or malformed token"}), 401
        
        token = auth_header.split(' ')[1]
        payload = decode_token(token)
        if 'error' in payload:
            return None, payload['error'], payload['status']
            
        return token, None
    except RuntimeError:
        # This happens when we're not in a request context
        return None, jsonify({"error": "No request context available"}), 500

def get_user_id_from_token(token: str) -> tuple[int | None, dict | None]:
    """Extract user ID from a JWT token.
    
    Args:
        token (str): The JWT token to extract user ID from
        
    Returns:
        tuple: (user_id, error_message) where either user_id or error_message will be None
    """
    payload = decode_token(token)
    if 'error' in payload:
        return None, payload['error'], payload['status']
    return payload['user_id'], None

def decode_token(token: str) -> dict:
    """Decode and validate a JWT token.
    
    Args:
        token (str): The JWT token to decode
        
    Returns:
        dict: The decoded token payload or error message
    """
    try:
        # First check if token is blacklisted
        db = Session()
        blacklisted = db.query(TokenBlacklist).filter_by(token=token).first()
        db.close()
        
        if blacklisted:
            return {'error': jsonify({'error': 'Token has been invalidated'}), 'status': 401}

        # Decode and validate the token
        payload = jwt.decode(token, current_app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
        
        # Ensure it's an access token
        if payload.get('type') != 'access':
            return {'error': jsonify({'error': 'Invalid token type'}), 'status': 401}

        return payload
    except jwt.ExpiredSignatureError:
        return {'error': jsonify({'error': 'Token has expired'}), 'status': 401}
    except jwt.InvalidTokenError:
        return {'error': jsonify({'error': 'Invalid token'}), 'status': 401}

def generate_token(user_id: int) -> tuple[str, str]:
    """Generate access and refresh tokens for a user.
    
    Args:
        user_id (int): The ID of the user to generate tokens for
        
    Returns:
        tuple: (access_token, refresh_token)
    """
    # Access token expires in configured hours
    access_expires_at = datetime.now(UTC) + config.jwt.access_token_expires
    
    access_payload = {
        'user_id': user_id,
        'exp': access_expires_at,
        'iat': datetime.now(UTC),
        'type': 'access'
    }
    access_token = jwt.encode(access_payload, current_app.config['JWT_SECRET_KEY'], algorithm='HS256')

    # Refresh token expires in configured days
    refresh_expires_at = datetime.now(UTC) + config.jwt.refresh_token_expires
    
    refresh_payload = {
        'user_id': user_id,
        'exp': refresh_expires_at,
        'iat': datetime.now(UTC),
        'type': 'refresh'
    }
    refresh_token = jwt.encode(refresh_payload, current_app.config['JWT_SECRET_KEY'], algorithm='HS256') #HMAC-SHA256

    return access_token, refresh_token

def refresh_access_token(refresh_token: str) -> tuple[str | None, dict | None]:
    """Generate a new access token using a refresh token.
    
    Args:
        refresh_token (str): The refresh token to use
        
    Returns:
        tuple: (new_access_token, error_message) where either token or error will be None
    """
    try:
        # Verify it's a refresh token
        payload = jwt.decode(refresh_token, current_app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
        if payload.get('type') != 'refresh':
            return None, jsonify({'error': 'Invalid token type'}), 401

        # Check if refresh token is blacklisted
        db = Session()
        blacklisted = db.query(TokenBlacklist).filter_by(token=refresh_token).first()
        db.close()
        
        if blacklisted:
            return None, jsonify({'error': 'Refresh token has been invalidated'}), 401

        # Generate new access token
        new_access_token, _ = generate_token(payload['user_id'])
        return new_access_token, None

    except jwt.ExpiredSignatureError:
        return None, jsonify({'error': 'Refresh token has expired'}), 401
    except jwt.InvalidTokenError:
        return None, jsonify({'error': 'Invalid refresh token'}), 401

def invalidate_token(token: str) -> bool:
    """Invalidate a JWT token by adding it to the blacklist.
    
    Args:
        token (str): The JWT token to invalidate
        
    Returns:
        bool: True if token was successfully invalidated, False otherwise
    """
    try:
        # Decode token to get expiration
        payload = jwt.decode(token, current_app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
        expires_at = datetime.fromtimestamp(payload['exp'], UTC)
        
        # Add to blacklist
        db = Session()
        blacklisted_token = TokenBlacklist(
            token=token,
            blacklisted_at=datetime.now(UTC),
            expires_at=expires_at
        )
        db.add(blacklisted_token)
        db.commit()
        db.close()
        return True
    except Exception:
        return False

#TODO this has to be called periodically!!!
def cleanup_expired_tokens(batch_size: int = 1000) -> None:
    """Remove expired tokens from the blacklist.
    
    Args:
        batch_size (int): Maximum number of tokens to delete in a single transaction. Defaults to 1000.
    """
    db = Session()
    try:
        while True:
            # Get a batch of expired tokens
            expired_tokens = db.query(TokenBlacklist).filter(
                TokenBlacklist.expires_at < datetime.now(UTC)
            ).limit(batch_size).all()
            
            if not expired_tokens:
                break
                
            # Delete the batch
            for token in expired_tokens:
                db.delete(token)
            db.commit()
            
            # If we got less than batch_size, we're done
            if len(expired_tokens) < batch_size:
                break
    finally:
        db.close() 