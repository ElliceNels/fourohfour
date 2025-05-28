import secrets
import base64

"""
Script to generate secure secret keys for Flask and JWT authentication.

This script generates cryptographically secure random keys that can be used for:
- Flask SECRET_KEY: Used for session security, CSRF protection, and flash messages
- JWT_SECRET_KEY: Used for signing and verifying JSON Web Tokens

Important Security Notes:
1. Keys should be stored in environment variables (.env file) and never hardcoded
2. Keys should be kept consistent across server restarts
3. Different keys should be used for development and production environments
4. Keys should never be committed to version control
5. Changing keys will invalidate all existing sessions/tokens

Usage:
    python generate_jwt_secret.py
    # Copy the output into your .env file
"""

def generate_secret_key():
    # Generate 32 random bytes and encode them in base64
    random_bytes = secrets.token_bytes(32)
    secret_key = base64.b64encode(random_bytes).decode('utf-8')
    return secret_key

if __name__ == "__main__":
    jwt_secret = generate_secret_key()
    flask_secret = generate_secret_key()
    
    print("\nGenerated Secret Keys:")
    print("\nJWT Secret Key:")
    print(jwt_secret)
    print("\nFlask Secret Key:")
    print(flask_secret)
    print("\nAdd these to your .env file as:")
    print(f"JWT_SECRET_KEY={jwt_secret}")
    print(f"SECRET_KEY={flask_secret}") 