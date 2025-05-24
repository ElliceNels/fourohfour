from datetime import datetime, UTC
from flask import jsonify
from src.server.models.tables import Users, Files, FilePermissions
from src.server.utils.db_setup import get_session

def get_user_public_key(user_id: int) -> dict:
    """Get the public key of a user.

    Args:
        user_id (int): ID of the user whose public key is requested

    Returns:
        dict: Response containing the user's public key or error message
    """
    try:
        with get_session() as db:
            user = db.query(Users).get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404

        return jsonify({
            'public_key': user.public_key
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

def create_file_permission(file_id: int, user_id: int, key_for_recipient: str, owner_id: int) -> dict:
    """Create a new file permission for a user.

    Args:
        file_id (int): ID of the file to share
        user_id (int): ID of the user to share with
        key_for_recipient (str): Symmetric file key encrypted with the recipient's public key
        owner_id (int): ID of the file owner

    Returns:
        dict: Response containing success message or error
    """
    with get_session() as db:
        try:
            # Check if the file exists and belongs to the owner
            file = db.query(Files).get(file_id)
            if not file:
                return jsonify({'error': 'File not found'}), 404
            if file.owner_id != owner_id:
                return jsonify({'error': 'Not authorized to share this file'}), 403

            # Check if the recipient user exists
            recipient = db.query(Users).get(user_id)
            if not recipient:
                return jsonify({'error': 'Recipient user not found'}), 404

            # Check if permission already exists
            existing_permission = db.query(FilePermissions).filter_by(
                file_id=file_id,
                user_id=user_id
            ).first()
            if existing_permission:
                return jsonify({'error': 'Permission already exists'}), 409

            # Create new permission
            new_permission = FilePermissions(
                file_id=file_id,
                user_id=user_id,
                encryption_key=key_for_recipient,
                created_at=datetime.now(UTC),
                updated_at=datetime.now(UTC)
            )
            db.add(new_permission)
            db.commit()

            return jsonify({'message': 'Permission created successfully'}), 201

        except Exception as e:
            db.rollback()
            return jsonify({'error': str(e)}), 500

def remove_file_permission(file_id: int, user_id: int, owner_id: int) -> dict:
    """Remove a file permission for a user.

    Args:
        file_id (int): ID of the file to remove permission from
        user_id (int): ID of the user to remove permission for
        owner_id (int): ID of the file owner

    Returns:
        dict: Response containing success message or error
    """
    with get_session() as db:
        try:
            # Check if the file exists and belongs to the owner
            file = db.query(Files).get(file_id)
            if not file:
                return jsonify({'error': 'File not found'}), 404
            if file.owner_id != owner_id:
                return jsonify({'error': 'Not authorized to modify permissions for this file'}), 403

            # Find and delete the permission
            permission = db.query(FilePermissions).filter_by(
                file_id=file_id,
                user_id=user_id
            ).first()
            
            if not permission:
                return jsonify({'error': 'Permission not found'}), 404

            db.delete(permission)
            db.commit()

            return jsonify({'message': 'Permission removed successfully'}), 200

        except Exception as e:
            db.rollback()
