from flask import Blueprint, jsonify, request
from server.utils.auth import get_current_user
from server.utils.permission import create_file_permission, remove_file_permission
from server.utils.db_setup import get_session
from server.models.tables import Files
from server.utils.permission import get_file_permissions
import logging

logger = logging.getLogger(__name__)

permission_bp = Blueprint('permissions', __name__, url_prefix='/api/permissions')

@permission_bp.route('', methods=['POST'])
def create_permission():
    """Create a new file permission.
    
    Expected JSON payload:
    {
        "file_uuid": <file_uuid>,
        "username": <username>,
        "key_for_recipient": "<encrypted_symmetric_key>",
        "otpk": "<one_time_pre_key>", #The otpk used
        "ephemeral_key": "<ephemeral_key>" #The ephemeral key used
    }

    Returns:
    {
        "message": "Permission created successfully"
    }
    """
    data = request.get_json()
    logger.debug(f"Received request to create file permission with data: {data}")
    if not data:
        logger.warning("No data provided")
        return jsonify({'error': 'No data provided'}), 400

    required_fields = ['file_uuid', 'username', 'key_for_recipient', "otpk", "ephemeral_key"]
    for field in required_fields:
        if field not in data:
            logger.warning(f"{field} is required")
            return jsonify({'error': f'{field} is required'}), 400

    try:
        current_user_info, status_code = get_current_user()
        if status_code != 200:
            return jsonify({'error': 'Authentication failed'}), status_code

        user_id = current_user_info['user_id']

        return create_file_permission(
            data['file_uuid'],
            data['username'],
            data['key_for_recipient'],
            data['otpk'],
            data['ephemeral_key'],
            user_id
        )
    except Exception as e:
        logger.error(f"Error creating file permission: {str(e)}")
        return jsonify({'error': str(e)}), 500

@permission_bp.route('', methods=['DELETE'])
def remove_permission():
    """Remove a file permission.
    
    Expected JSON payload:
    {
        "file_uuid": <file_uuid>,
        "username": <username>
    }

    Returns:
    {
        "message": "Permission removed successfully"
    }
    """
    data = request.get_json()
    logger.debug(f"Received request to remove file permission with data: {data}")

    if not data:
        logger.warning("No data provided")
        return jsonify({'error': 'No data provided'}), 400

    required_fields = ['file_uuid', 'username']
    for field in required_fields:
        if field not in data:
            logger.warning(f"{field} is required")
            return jsonify({'error': f'{field} is required'}), 400

    try:
        current_user_info, status_code = get_current_user()
        if status_code != 200:
            return jsonify({'error': 'Authentication failed'}), status_code

        user_id = current_user_info['user_id']

        return remove_file_permission(
            data['file_uuid'],
            data['username'],
            user_id
        )
    except Exception as e:
        logger.error(f"Error removing file permission: {str(e)}")
        return jsonify({'error': str(e)}), 500

@permission_bp.route('/<file_uuid>', methods=['GET'])
def get_permissions(file_uuid):
    """Get all permissions for a specific file (only if the caller is owner)
    
    Returns:
    {
        "permissions": [
            {
                "username": <username>,
            },
            ...
        ]
    }
    """
    logger.debug(f"Received request to get permissions for file UUID: {file_uuid}")

    if not file_uuid:
        logger.warning("File UUID is required")
        return jsonify({'error': 'File UUID is required'}), 400

    try:
        user_info, status_code = get_current_user()
        if status_code != 200:
            return jsonify({'error': 'Authentication failed'}), status_code

        return get_file_permissions(file_uuid, user_info['id'])
    except Exception as e:
        logger.error(f"Error retrieving permissions: {str(e)}")
        return jsonify({'error': str(e)}), 500