from datetime import datetime, UTC
from flask import jsonify
from server.models.tables import Users, Files, FilePermissions, OTPK
from server.utils.db_setup import get_session
import logging
import base64

logger = logging.getLogger(__name__)

def create_file_permission(file_uuid: str, username: str, key_for_recipient: str, otpk: str, ephemeral_key: str, owner_id: int) -> dict:
    """Create a new file permission for a user.

    Args:
        file_uuid (str): UUID of the file to share
        username (str): Username of the user to share with
        key_for_recipient (str): Symmetric file key encrypted with the recipient's public key
        otpk (str): One-time pre-key used for encryption
        ephemeral_key (str): Ephemeral key used for encryption
        owner_id (int): ID of the file owner

    Returns:
        dict: Response containing success message or error
    """
    logger.info(f"Attempting to create file permission - file_uuid: {file_uuid}, username: {username}, owner_id: {owner_id}")
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
            logger.debug(f"Querying for recipient user with username: {username}")
            recipient = db.query(Users).filter_by(username=username).first()
            if not recipient:
                logger.warning(f"Recipient user with username {username} not found")
                return jsonify({'error': 'Recipient user not found'}), 404

            # Check if permission already exists
            logger.debug(f"Checking for existing permission - file_uuid: {file_uuid}, username: {username}")
            existing_permission = db.query(FilePermissions).filter_by(
                file_id=file.id,
                user_id=recipient.id
            ).first()
            if existing_permission:
                logger.warning(f"Permission already exists for file {file_uuid} and user {username}")
                return jsonify({'error': 'Permission already exists'}), 409

            # Create new permission
            logger.debug("Creating new permission record")
            # Validate the keys are valid base64 strings
            try:
                # Just validate the format without converting to bytes
                base64.b64decode(key_for_recipient)
                base64.b64decode(otpk)
                base64.b64decode(ephemeral_key)
            except Exception as e:
                logger.error(f"Error validating encryption keys: {str(e)}")
                return jsonify({'error': 'Invalid encryption key format'}), 400

            # Create OTPK record first
            new_otpk = OTPK(
                user_id=recipient.id,
                key=otpk,
                used=1,  # Mark as used since it's being used for this permission
                created_at=datetime.now(UTC),
                updated_at=datetime.now(UTC)
            )
            db.add(new_otpk)
            db.flush()  # Flush to get the ID without committing

            new_permission = FilePermissions(
                file_id=file.id,
                user_id=recipient.id,
                encryption_key=key_for_recipient,
                otpk_id=new_otpk.id,  # Use the ID of the newly created OTPK
                ephemeral_key=ephemeral_key,
                created_at=datetime.now(UTC),
                updated_at=datetime.now(UTC)
            )
            db.add(new_permission)
            db.commit()
            logger.info(f"Permission created for file {file_uuid} and user {username} successfully")
            return jsonify({'message': 'Permission created successfully'}), 201

        except Exception as e:
            db.rollback()
            logger.error(f"Error creating permission for file {file_uuid} and user {username}: {str(e)}", exc_info=True)
            return jsonify({'error': str(e)}), 500

def remove_file_permission(file_uuid: str, username: str, sender_username: str, sender_id: int) -> dict:
    """Remove a file permission for a user.

    Args:
        file_uuid (str): UUID of the file to remove permission from
        username (str): Username of the user to remove permission for
        sender_username (str): Username of the user requesting permission removal
        sender_id (int): ID of the user requesting permission removal

    Returns:
        dict: Response containing success message or error
    """
    logger.info(f"Attempting to remove file permission - file_uuid: {file_uuid}, username: {username}, sender_id: {sender_id}")
    with get_session() as db:
        try:
            # Check if the file exists
            logger.debug(f"Querying for file with UUID: {file_uuid}")
            file = db.query(Files).filter_by(uuid=file_uuid).first()
            if not file:
                logger.warning(f"File with UUID {file_uuid} not found for user {sender_id}")
                return jsonify({'error': 'File not found'}), 404

            # Check if user is authorized to modify permissions
            # User can remove permission if they are either:
            # 1. The owner of the file
            # 2. The user whose permission is being removed
            logger.debug(f"Found file - owner_id: {file.owner_id}, sender_id: {sender_id}")
            if file.owner_id != sender_id and sender_username != username:
                logger.warning(f"User {sender_id} is not authorized to modify permissions for file {file_uuid}")
                return jsonify({'error': 'Not authorized to modify permissions for this file'}), 403

            # Find and delete the permission
            user = db.query(Users).filter_by(username=username).first()
            if not user:
                logger.warning(f"User with username {username} not found")
                return jsonify({'error': 'User not found'}), 404
            logger.debug(f"Looking for permission - file_uuid: {file_uuid}, username: {username}")
            permission = db.query(FilePermissions).filter_by(
                file_id=file.id,
                user_id=user.id
            ).first()
            
            if not permission:
                logger.warning(f"Permission not found for file {file_uuid} and user {username}")
                return jsonify({'error': 'Permission not found'}), 404

            db.delete(permission)
            db.commit()

            logger.info(f"Permission removed for file {file_uuid} and user {username} successfully")
            return jsonify({'message': 'Permission removed successfully'}), 200

        except Exception as e:
            db.rollback()
            logger.error(f"Error removing permission for file {file_uuid} and user {username}: {str(e)}", exc_info=True)
            return jsonify({'error': str(e)}), 500

def get_file_permissions(file_uuid: str, user_id: int) -> dict:
    """Get all permissions for a specific file.

    Args:
        file_uuid (str): UUID of the file to get permissions for
        owner_id (int): ID of the file owner

    Returns:
        dict: Response containing permissions list or error
    """
    logger.info(f"Attempting to get permissions for file - file_uuid: {file_uuid}")
    with get_session() as db:
        try:
            # Check if the file exists and belongs to the owner
            logger.debug(f"Querying for file with UUID: {file_uuid}")
            file = db.query(Files).filter_by(uuid=file_uuid).first()
            if not file:
                logger.warning(f"File with UUID {file_uuid} not found")
                return jsonify({'error': 'File not found'}), 404

            # Check if user is authorized to view permissions
            if file.owner_id != user_id:
                logger.warning(f"User is not authorized to view permissions for file {file_uuid}")
                return jsonify({'error': 'Not authorized to view permissions for this file'}), 403

            # Get all permissions for the file
            permissions = db.query(FilePermissions).filter_by(file_id=file.id).all()
            
            # Format permissions for response
            formatted_permissions = []
            for perm in permissions:
                user = db.query(Users).filter_by(id=perm.user_id).first()
                if user:
                    formatted_permissions.append({
                        'username': user.username,
                    })

            logger.info(f"Successfully retrieved {len(formatted_permissions)} permissions for file {file_uuid}")
            return jsonify({'permissions': formatted_permissions}), 200

        except Exception as e:
            logger.error(f"Error getting permissions for file {file_uuid}: {str(e)}", exc_info=True)
            return jsonify({'error': str(e)}), 500