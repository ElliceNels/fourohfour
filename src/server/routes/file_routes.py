from flask import Blueprint, jsonify, request
from src.server.models.tables import Files, FilePermissions, Users, FileMetadata  
from src.server.utils.auth import get_current_user
from src.server.utils.file import upload_file_to_db, get_user_files, get_file_by_id, delete_file_by_id
from werkzeug.utils import secure_filename
import os
from datetime import datetime, UTC
import logging

logger = logging.getLogger(__name__)

files_bp = Blueprint('files', __name__, url_prefix='/api/files')

@files_bp.route('/upload', methods=['POST'])
def upload_file():
    """Upload a new file to the system.
    
    Expected request:
    - encrypted_file: The encrypted file data in request.files
    - metadata: JSON object containing:
        - size: File size in bytes
        - format: File format/extension

    Returns:
    {
        "message": "File uploaded successfully",
        "file_id": <file_id>
    }
    """
    logger.debug(f"Received file upload request")

    if 'encrypted_file' not in request.files:
        logger.warning("Upload failed: No file provided")
        return jsonify({'error': 'No file provided'}), 400

    try:
        current_user = get_current_user()
        
        # Save the file to disk
        file = request.files['encrypted_file']
        sanitized_filename = secure_filename(file.filename)
        filename = f"{current_user.user_id}_{sanitized_filename}"
        file_path = os.path.join('uploads', filename)
        file.save(file_path)

        return upload_file_to_db(current_user.user_id, file, file_path, request.metadata)

    except Exception as e:
        # Clean up file if database operation fails
        if 'file_path' in locals():
            try:
                os.remove(file_path)
            except:
                pass
        logger.error(f"Error uploading file: {str(e)}")
        return jsonify({'error': str(e)}), 500

@files_bp.route('/', methods=['GET'])
def list_files():
    """List all files accessible to the authenticated user.
    
    Returns:
    {
        "owned_files": [
            {
                "id": <file_id>,
                "filename": <filename>,
                "file_size": <size>,
                "format": <format>,
                "uploaded_at": <timestamp>,
                "is_owner": true
            }
        ],
        "shared_files": [
            {
                "id": <file_id>,
                "filename": <filename>,
                "file_size": <size>,
                "format": <format>,
                "uploaded_at": <timestamp>,
                "is_owner": false
            }
        ]
    }
    """
    logger.debug("Received request to list files")

    try:
        current_user = get_current_user()
        return get_user_files(current_user.user_id)
    except Exception as e:
        logger.error(f"Error listing files: {str(e)}")
        return jsonify({'error': str(e)}), 500

@files_bp.route('/<file_id>', methods=['GET'])
def get_file(file_id):
    """Get a specific file by ID.
    
    Args:
        file_id: The ID of the requested file

    Returns:
    {
        "encrypted_file": <base64_encoded_file_data>,
        "encrypted_keys": {  # Only included if user is owner
            <user_id>: <encryption_key>
        }
    }
    """
    logger.debug(f"Received request to get file with ID: {file_id}")

    try:
        current_user = get_current_user()
        return get_file_by_id(file_id, current_user.user_id)
    except Exception as e:
        logger.error(f"Error retrieving file {file_id}: {str(e)}")
        return jsonify({'error': str(e)}), 500

@files_bp.route('/<file_id>', methods=['DELETE'])
def delete_file(file_id):
    """Delete a specific file by ID.
    
    Args:
        file_id: The ID of the file to delete

    Returns:
    {
        "message": "File deleted successfully"
    }
    """
    logger.debug(f"Received request to delete file with ID: {file_id}")

    try:
        current_user = get_current_user()
        return delete_file_by_id(file_id, current_user.user_id)
    except Exception as e:
        logger.error(f"Error deleting file {file_id}: {str(e)}")
        return jsonify({'error': str(e)}), 500