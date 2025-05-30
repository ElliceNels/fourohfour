from datetime import datetime, UTC
import jwt
from flask import jsonify, current_app, request
from server.config import config 
from server.utils.db_setup import get_session
from server.models.tables import TokenInvalidation

class JWTError(Exception):
    def __init__(self, message, status):
        super().__init__(message)
        self.message = message
        self.status = status


def decode_token(token: str) -> dict:
    """Decode and validate a JWT token.
    
    Args:
        token (str): The JWT token to decode
        
    Returns:
        dict: The decoded token payload
    
    Raises:
        JWTError: If the token is invalid, expired, or otherwise not usable
    """
    try:
        payload = jwt.decode(token, current_app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
        
        # Check if token is invalidated by checking if its iat is before the earliest valid iat
        with get_session() as db:
            invalidation = db.query(TokenInvalidation).filter_by(user_id=payload['user_id']).first()
        
        if invalidation and datetime.fromtimestamp(payload['iat'], UTC) < invalidation.earliest_valid_iat:
            raise JWTError('Token has been invalidated', 401)
        
        # Ensure it's an access token
        if payload.get('type') != 'access':
            raise JWTError('Invalid token type', 401)

        return payload
    except jwt.ExpiredSignatureError:
        raise JWTError('Token has expired', 401)
    except jwt.InvalidTokenError:
        raise JWTError('Invalid token', 401)

def get_current_token() -> str:
    """Extract and validate the JWT token from the Authorization header.
    Returns:
        str: The JWT token string
    Raises:
        JWTError: If the token is missing, malformed, or invalid
    """
    try:
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            raise JWTError('Missing or malformed token', 401)
        
        token = auth_header.split(' ')[1]
        decode_token(token)  # Will raise if invalid
        return token
    except RuntimeError:
        raise JWTError('No request context available', 500)

def get_user_id_from_token(token: str) -> int:
    """Extract user ID from a JWT token.
    Args:
        token (str): The JWT token to extract user ID from
    Returns:
        int: The user ID
    Raises:
        JWTError: If the token is invalid or user_id is missing
    """
    payload = decode_token(token)
    return payload['user_id']

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

def refresh_access_token(refresh_token: str) -> str:
    """Generate a new access token using a refresh token.
    Args:
        refresh_token (str): The refresh token to use
    Returns:
        str: The new access token
    Raises:
        JWTError: If the refresh token is invalid or expired
    """
    try:
        payload = jwt.decode(refresh_token, current_app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
        if payload.get('type') != 'refresh':
            raise JWTError('Invalid token type', 401)

        # Check if token is invalidated by checking if its iat is before the earliest valid iat
        with get_session() as db:
            invalidation = db.query(TokenInvalidation).filter_by(user_id=payload['user_id']).first()
        
        if invalidation and datetime.fromtimestamp(payload['iat'], UTC) < invalidation.earliest_valid_iat:
            raise JWTError('Token has been invalidated', 401)
        # Generate new access token
        new_access_token, _ = generate_token(payload['user_id'])
        return new_access_token

    except jwt.ExpiredSignatureError:
        raise JWTError('Token has expired', 401)
    except jwt.InvalidTokenError:
        raise JWTError('Invalid token', 401)

def invalidate_token(token: str) -> bool:
    """Invalidate a JWT token by updating the earliest valid token issue date for the user.
    
    Args:
        token (str): The JWT token to invalidate
        
    Returns:
        bool: True if token was successfully invalidated, False otherwise
    """
    try:
        # Decode token to get user_id
        payload = jwt.decode(token, current_app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
        user_id = payload['user_id']
        
        # Set earliest_valid_iat to current time to invalidate all existing tokens
        earliest_valid_iat = datetime.now(UTC)
        
        # Update or create token invalidation record
        with get_session() as db:
            invalidation = db.query(TokenInvalidation).filter_by(user_id=user_id).first()
            
            if invalidation:
                invalidation.earliest_valid_iat = earliest_valid_iat
                invalidation.updated_at = datetime.now(UTC)
            else:
                # Create new record
                invalidation = TokenInvalidation(
                    user_id=user_id,
                    earliest_valid_iat=earliest_valid_iat
                )
                db.add(invalidation)
                
            db.commit()
        return True
    except Exception:
        return False

def cleanup_expired_invalidations() -> None:
    """Remove token invalidation records that are no longer needed.
    A record can be removed if all tokens issued before its earliest_valid_iat have expired.
    """
    with get_session() as db:
        # Get all invalidation records
        invalidations = db.query(TokenInvalidation).all()
        now = datetime.now(UTC)
        
        for invalidation in invalidations:
            # If the earliest_valid_iat + max_token_ttl is in the past, we can remove this record
            max_token_ttl = max(config.jwt.access_token_expires, config.jwt.refresh_token_expires)
            if invalidation.earliest_valid_iat + max_token_ttl < now:
                db.delete(invalidation)
        
        db.commit()