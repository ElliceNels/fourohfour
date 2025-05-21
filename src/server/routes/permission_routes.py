from flask import Blueprint, jsonify, request
from ..models.tables import Users, Files, FilePermissions 
from ..utils.auth import get_current_user  # Assuming we have this utility for now. Spoiler, we don't
from datetime import datetime

permission_bp = Blueprint('permissions', __name__, url_prefix='/api/permissions')

@permission_bp.route('/public_key', methods=['GET'])
def get_public_key():
    """
    Get the public key of a user
    Expects:
    - user_id: The ID of the user
    """
    user_id = request.args.get('user_id')
    if not user_id:
        return jsonify({'error': 'user_id is required'}), 400

    try:
        user = Users.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404

        return jsonify({
            'public_key': user.public_key
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@permission_bp.route('', methods=['POST'])
def create_permission():
    """
    Creates a new permission
    Expects:
    - file_id: The ID of the file
    - user_id: The ID of the user
    - key_for_recipient: The symmetric file key encrypted with the user_id public key
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
        
        # Check if the file exists and belongs to the current user
        file = Files.query.get(data['file_id'])
        if not file:
            return jsonify({'error': 'File not found'}), 404
        if file.owner_id != current_user.id:
            return jsonify({'error': 'Not authorized to share this file'}), 403

        # Check if the recipient user exists
        recipient = Users.query.get(data['user_id'])
        if not recipient:
            return jsonify({'error': 'Recipient user not found'}), 404

        # Check if permission already exists
        existing_permission = FilePermissions.query.filter_by(
            file_id=data['file_id'],
            user_id=data['user_id']
        ).first()
        if existing_permission:
            return jsonify({'error': 'Permission already exists'}), 409

        # Create new permission
        new_permission = FilePermissions(
            file_id=data['file_id'],
            user_id=data['user_id'],
            encryption_key=data['key_for_recipient'],
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        db.session.add(new_permission)
        db.session.commit()

        return jsonify({'message': 'Permission created successfully'}), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@permission_bp.route('', methods=['DELETE'])
def remove_permission():
    """
    Removes a permission from a file
    Expects:
    - file_id: The ID of the file
    - user_id: The ID of the user
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
        
        # Check if the file exists and belongs to the current user
        file = Files.query.get(data['file_id'])
        if not file:
            return jsonify({'error': 'File not found'}), 404
        if file.owner_id != current_user.id:
            return jsonify({'error': 'Not authorized to modify permissions for this file'}), 403

        # Find and delete the permission
        permission = FilePermissions.query.filter_by(
            file_id=data['file_id'],
            user_id=data['user_id']
        ).first()
        
        if not permission:
            return jsonify({'error': 'Permission not found'}), 404

        db.session.delete(permission)
        db.session.commit()

        return jsonify({'message': 'Permission removed successfully'}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500