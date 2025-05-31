from flask import Blueprint, jsonify, request
from server.utils.auth import get_current_user
from server.utils.permission import create_file_permission, remove_file_permission
from server.utils.db_setup import get_session
from server.models.tables import Files
import logging

logger = logging.getLogger(__name__)

permission_bp = Blueprint('permissions', __name__, url_prefix='/api/permissions')

@permission_bp.route('', methods=['POST'])
def create_permission():
    """Create a new file permission.
    
    Expected JSON payload:
    {
        "file_uuid": <file_uuid>,
        "user_id": <user_id>,
        "key_for_recipient": "<encrypted_symmetric_key>"
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

    required_fields = ['file_uuid', 'user_id', 'key_for_recipient']
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
            data['user_id'],
            data['key_for_recipient'],
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
        "user_id": <user_id>
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

    required_fields = ['file_uuid', 'user_id']
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
            data['user_id'],
            user_id
        )
    except Exception as e:
        logger.error(f"Error removing file permission: {str(e)}")
        return jsonify({'error': str(e)}), 500