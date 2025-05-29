import secrets
import base64
import os
import argparse
from pathlib import Path

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
    python generate_secret_key.py [--force] [--key KEY_NAME]
    # --force: Force replacement of existing key
    # --key: Name of the environment variable to generate (e.g., JWT_SECRET_KEY or SECRET_KEY)
"""

def generate_secret_key():
    # Generate 32 random bytes and encode them in base64
    random_bytes = secrets.token_bytes(32)
    secret_key = base64.b64encode(random_bytes).decode('utf-8')
    return secret_key

def update_env_file(key_name, secret_key, force=False):
    # Get the script's directory and navigate to src/server
    script_dir = Path(__file__).parent
    server_dir = script_dir.parent
    env_path = server_dir / '.env'
    
    existing_vars = {}
    
    # Read existing .env file if it exists
    if env_path.exists():
        with open(env_path, 'r') as f:
            for line in f:
                if '=' in line:
                    key, value = line.strip().split('=', 1)
                    existing_vars[key] = value
    
    # Check if key exists and handle accordingly
    if not force and key_name in existing_vars:
        print(f"\nWarning: {key_name} already exists in .env file.")
        print("Use --force flag to replace existing key.")
        return
    
    # Update the variable
    existing_vars[key_name] = secret_key
    
    # Write back to .env file
    with open(env_path, 'w') as f:
        for key, value in existing_vars.items():
            f.write(f"{key}={value}\n")
    
    print(f"\nSuccessfully updated .env file with new {key_name}.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Generate secret keys for Flask and JWT')
    parser.add_argument('--force', action='store_true', help='Force replacement of existing key')
    parser.add_argument('--key', required=True, help='Name of the environment variable to generate (e.g., JWT_SECRET_KEY or SECRET_KEY)')
    args = parser.parse_args()
    
    secret_key = generate_secret_key()
    update_env_file(args.key, secret_key, args.force) 