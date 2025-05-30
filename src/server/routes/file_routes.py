from flask import Blueprint, jsonify, request
from server.models.tables import Files, FilePermissions, Users, FileMetadata  
from server.utils.auth import get_current_user
from server.utils.file import upload_file_to_db, get_user_files, get_file_by_uuid, delete_file_by_uuid
from werkzeug.utils import secure_filename
import os
from datetime import datetime, UTC
import logging
import uuid

logger = logging.getLogger(__name__)

files_bp = Blueprint('files', __name__, url_prefix='/api/files')

@files_bp.route('/upload', methods=['POST'])
def upload_file():
    """Upload a new file to the system.
    
    Expected request:
    {
        "file": {
            "filename": "name_of_file",
            "contents": "base64_encoded_file_data",
            "uuid" (optional) : "uuid_of_file_to_update"
        },
        "metadata": {
            "size": 123,
            "format": "txt"
        }
    }

    Returns:
    {
        "message": "File uploaded successfully",
        "uuid": <uuid>
    }
    """
    logger.debug(f"Received file upload request")
    data = request.get_json()
    if not data or 'file' not in data:
        logger.warning("Upload failed: Invalid request format")
        return jsonify({'error': 'Invalid request format'}), 400
    
    file_data = data['file']
    if 'filename' not in file_data or 'contents' not in file_data:
        logger.warning("Upload failed: Missing filename or contents")
        return jsonify({'error': 'Missing filename or contents'}), 400

    try:
        current_user = get_current_user()
        
        # Get UUID parameter
        file_uuid = file_data.get('uuid')
        # Get custom filename if provided, otherwise use the uploaded file's name
        custom_filename = file_data.get('filename')
        file = request.files['encrypted_file']
        
        # File is a Werkzeug type, it has a filename attribute which we can override
        if custom_filename:
            file.filename = custom_filename
        
        # Validate UUID format if provided
        if file_uuid:
            try:
                file_uuid = uuid.UUID(file_uuid)
            except ValueError:
                logger.warning(f"Invalid UUID format provided: {file_uuid}")
                return jsonify({'error': 'Invalid UUID format'}), 400
        
        # Save the file to disk
        sanitized_filename = secure_filename(file.filename) #sanitize to remove any unsafe characters
        system_filename = f"{current_user.user_id}_{sanitized_filename}"
        file_path = os.path.join('uploads', system_filename)
        file.save(file_path)

        return upload_file_to_db(current_user.user_id, file, file_path, request.metadata, file_uuid)

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
                "uuid": <uuid>,
                "filename": <filename>,
                "file_size": <size>,
                "format": <format>,
                "uploaded_at": <timestamp>,
                "is_owner": true
            }
        ],
        "shared_files": [
            {
                "uuid": <uuid>,
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

@files_bp.route('/<file_uuid>', methods=['GET'])
def get_file(file_uuid):
    """Get a specific file by UUID.
    
    Args:
        file_uuid: The UUID of the requested file

    Returns:
    {
        "encrypted_file": <base64_encoded_file_data>,
        "encrypted_keys": {  # Only included if user is owner
            <user_id>: <encryption_key>
        }
    }
    """
    logger.debug(f"Received request to get file with UUID: {file_uuid}")

    try:
        current_user = get_current_user()
        return get_file_by_uuid(file_uuid, current_user.user_id)
    except Exception as e:
        logger.error(f"Error retrieving file {file_uuid}: {str(e)}")
        return jsonify({'error': str(e)}), 500

@files_bp.route('/<file_uuid>', methods=['DELETE'])
def delete_file(file_uuid):
    """Delete a specific file by UUID.
    
    Args:
        file_uuid: The UUID of the file to delete

    Returns:
    {
        "message": "File deleted successfully"
    }
    """
    logger.debug(f"Received request to delete file with UUID: {file_uuid}")

    try:
        current_user = get_current_user()
        return delete_file_by_uuid(file_uuid, current_user.user_id)
    except Exception as e:
        logger.error(f"Error deleting file {file_uuid}: {str(e)}")
        return jsonify({'error': str(e)}), 500