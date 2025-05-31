from datetime import datetime, UTC
from flask import jsonify
from server.models.tables import Users, Files, FilePermissions
from server.utils.db_setup import get_session
import logging

logger = logging.getLogger(__name__)

def create_file_permission(file_id: int, user_id: int, key_for_recipient: str, owner_id: int) -> dict:
    """Create a new file permission for a user.

    Args:
        file_uuid (str): UUID of the file to share
        user_id (int): ID of the user to share with
        key_for_recipient (str): Symmetric file key encrypted with the recipient's public key
        owner_id (int): ID of the file owner

    Returns:
        dict: Response containing success message or error
    """
    logger.info(f"Attempting to create file permission - file_uuid: {file_uuid}, user_id: {user_id}, owner_id: {owner_id}")
    with get_session() as db:
        try:
            # Check if the file exists and belongs to the owner
            logger.debug(f"Querying for file with UUID: {file_uuid}")
            file = db.query(Files).filter_by(uuid=file_uuid).first()
            if not file:
                logger.warning(f"File with UUID {file_uuid} not found for user {owner_id}")
                return jsonify({'error': 'File not found'}), 404

            # Check if user is authorized to share the file
            logger.debug(f"Found file - owner_id: {file.owner_id}, expected owner_id: {owner_id}")
            if file.owner_id != owner_id:
                logger.warning(f"User {owner_id} is not authorized to share file {file_uuid}")
                return jsonify({'error': 'Not authorized to share this file'}), 403

            # Check if the recipient user exists
            logger.debug(f"Querying for recipient user with ID: {user_id}")
            recipient = db.get(Users, user_id)
            if not recipient:
                logger.warning(f"Recipient user with ID {user_id} not found")
                return jsonify({'error': 'Recipient user not found'}), 404

            # Check if permission already exists
            logger.debug(f"Checking for existing permission - file_uuid: {file.uuid}, user_id: {user_id}")
            existing_permission = db.query(FilePermissions).filter_by(
                file_id=file.id,
                user_id=user_id
            ).first()
            if existing_permission:
                logger.warning(f"Permission already exists for file {file_uuid} and user {user_id}")
                return jsonify({'error': 'Permission already exists'}), 409

            # Create new permission
            logger.debug("Creating new permission record")
            # Encode the encryption key as bytes
            try:
                encryption_key_bytes = key_for_recipient.encode('utf-8')
            except Exception as e:
                logger.error(f"Error encoding encryption key: {str(e)}")
                return jsonify({'error': 'Invalid encryption key format'}), 400

            new_permission = FilePermissions(
                file_id=file.id,
                user_id=user_id,
                encryption_key=encryption_key_bytes,
                created_at=datetime.now(UTC),
                updated_at=datetime.now(UTC)
            )
            db.add(new_permission)
            db.commit()
            logger.info(f"Permission created for file {file_uuid} and user {user_id} successfully")
            return jsonify({'message': 'Permission created successfully'}), 201

        except Exception as e:
            db.rollback()
            logger.error(f"Error creating permission for file {file_uuid} and user {user_id}: {str(e)}", exc_info=True)
            return jsonify({'error': str(e)}), 500

def remove_file_permission(file_uuid: str, user_id: int, owner_id: int) -> dict:
    """Remove a file permission for a user.

    Args:
        file_uuid (str): UUID of the file to remove permission from
        user_id (int): ID of the user to remove permission for
        owner_id (int): ID of the file owner

    Returns:
        dict: Response containing success message or error
    """
    logger.info(f"Attempting to remove file permission - file_uuid: {file_uuid}, user_id: {user_id}, owner_id: {owner_id}")
    with get_session() as db:
        try:
            # Check if the file exists and belongs to the owner
            logger.debug(f"Querying for file with UUID: {file_uuid}")
            file = db.query(Files).filter_by(uuid=file_uuid).first()
            if not file:
                logger.warning(f"File with UUID {file_uuid} not found for user {owner_id}")
                return jsonify({'error': 'File not found'}), 404

            # Check if user is authorized to modify permissions
            logger.debug(f"Found file - owner_id: {file.owner_id}, expected owner_id: {owner_id}")
            if file.owner_id != owner_id:
                logger.warning(f"User {owner_id} is not authorized to modify permissions for file {file_uuid}")
                return jsonify({'error': 'Not authorized to modify permissions for this file'}), 403

            # Find and delete the permission
            logger.debug(f"Looking for permission - file_uuid: {file.uuid}, user_id: {user_id}")
            permission = db.query(FilePermissions).filter_by(
                file_id=file.id,
                user_id=user_id
            ).first()
            
            if not permission:
                logger.warning(f"Permission not found for file {file_uuid} and user {user_id}")
                return jsonify({'error': 'Permission not found'}), 404

            db.delete(permission)
            db.commit()

            logger.info(f"Permission removed for file {file_uuid} and user {user_id} successfully")
            return jsonify({'message': 'Permission removed successfully'}), 200

        except Exception as e:
            db.rollback()
            logger.error(f"Error removing permission for file {file_uuid} and user {user_id}: {str(e)}", exc_info=True)
            return jsonify({'error': str(e)}), 500
