from flask import Blueprint, jsonify, request
from src.server.utils.auth import get_current_user
from src.server.utils.permission import get_user_public_key, create_file_permission, remove_file_permission

permission_bp = Blueprint('permissions', __name__, url_prefix='/api/permissions')

@permission_bp.route('/public_key', methods=['GET'])
def get_public_key():
    """Get the public key of a user.
    
    Query Parameters:
        user_id: The ID of the user whose public key is requested

    Returns:
    {
        "public_key": "<user_public_key>"
    }
    """
    user_id = request.args.get('user_id')
    if not user_id:
        return jsonify({'error': 'user_id is required'}), 400

    try:
        return get_user_public_key(int(user_id))
    except ValueError:
        return jsonify({'error': 'Invalid user_id format'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@permission_bp.route('', methods=['POST'])
def create_permission():
    """Create a new file permission.
    
    Expected JSON payload:
    {
        "file_id": <file_id>,
        "user_id": <user_id>,
        "key_for_recipient": "<encrypted_symmetric_key>"
    }

    Returns:
    {
        "message": "Permission created successfully"
    }
    """
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    required_fields = ['file_id', 'user_id', 'key_for_recipient']
    for field in required_fields:
        if field not in data:
            return jsonify({'error': f'{field} is required'}), 400

    try:
        current_user = get_current_user()
        return create_file_permission(
            data['file_id'],
            data['user_id'],
            data['key_for_recipient'],
            current_user.user_id
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@permission_bp.route('', methods=['DELETE'])
def remove_permission():
    """Remove a file permission.
    
    Expected JSON payload:
    {
        "file_id": <file_id>,
        "user_id": <user_id>
    }

    Returns:
    {
        "message": "Permission removed successfully"
    }
    """
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    required_fields = ['file_id', 'user_id']
    for field in required_fields:
        if field not in data:
            return jsonify({'error': f'{field} is required'}), 400

    try:
        current_user = get_current_user()
        return remove_file_permission(
            data['file_id'],
            data['user_id'],
            current_user.user_id
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500