from datetime import datetime, UTC
from flask import jsonify
import os
import base64
import uuid
from server.models.tables import Files, FilePermissions, FileMetadata
from server.utils.db_setup import get_session
import logging
from werkzeug.utils import secure_filename

logger = logging.getLogger(__name__)

def upload_file_to_db(user_id: int, filename: str, file_contents_b64: str, metadata: dict, file_uuid: uuid.UUID = None) -> dict:
    """Upload a file to the database and disk storage."""
    
    # Add validation for missing file FIRST, before any other operations
    if not filename or not file_contents_b64:
        logger.warning("Upload failed: Missing filename or file contents")
        return jsonify({'error': 'Missing filename or file contents'}), 400
    
    # Decode base64 contents
    try:
        import base64
        file_contents = base64.b64decode(file_contents_b64)
    except Exception as e:
        logger.error(f"Error decoding base64 file contents: {str(e)}")
        return jsonify({'error': 'Invalid base64 file contents'}), 400

    with get_session() as db:
        try:
            # Check if file with UUID exists
            existing_file = None
            if file_uuid:
                existing_file = db.query(Files).filter_by(uuid=file_uuid).first()
                
                if existing_file:
                    if existing_file.owner_id != user_id:
                        logger.warning(f"User {user_id} attempted to overwrite file {file_uuid} they don't own")
                        return jsonify({'error': 'Not authorized to overwrite this file'}), 403
                    
                    # Delete old file from disk
                    try:
                        os.remove(existing_file.path)
                    except Exception as e:
                        logger.error(f"Error deleting old file {existing_file.path}: {str(e)}")
                        return jsonify({'error': 'Error deleting old file'}), 500
                    
                    # Create new file path and save
                    sanitized_filename = secure_filename(filename)
                    system_filename = f"{user_id}_{sanitized_filename}"
                    file_path = os.path.join('uploads', system_filename)
                    
                    os.makedirs('uploads', exist_ok=True)
                    with open(file_path, 'wb') as f:
                        f.write(file_contents)
                    
                    # Update existing file record
                    existing_file.name = filename
                    existing_file.path = file_path
                    existing_file.uploaded_at = datetime.now(UTC)
                    
                    # Update metadata
                    if existing_file.file_metadata:
                        existing_file.file_metadata.size = metadata['size']
                        existing_file.file_metadata.format = metadata['format']
                        existing_file.file_metadata.last_updated_at = datetime.now(UTC)
                    else:
                        file_metadata = FileMetadata(
                            file_id=existing_file.id,
                            size=metadata['size'],
                            format=metadata['format'],
                            last_updated_at=datetime.now(UTC)
                        )
                        db.add(file_metadata)
                    
                    db.commit()
                    logger.info(f"File {filename} updated successfully by user {user_id}")
                    return jsonify({
                        'message': 'File updated successfully',
                        'uuid': str(existing_file.uuid)
                    }), 201
                else:
                    logger.warning(f"File with UUID {file_uuid} not found for overwrite")
                    return jsonify({'error': 'File not found to overwrite'}), 404

            # Check if user already has a file with the same name
            existing_file = db.query(Files).filter_by(
                owner_id=user_id,
                name=filename
            ).first()
            
            if existing_file:
                logger.warning(f"User {user_id} attempted to upload file with existing name: {filename}")
                return jsonify({
                    'error': 'File with this name already exists',
                    'uuid': str(existing_file.uuid)
                }), 409

            # Create file path and save to disk ONLY after validation passes
            sanitized_filename = secure_filename(filename)
            system_filename = f"{user_id}_{sanitized_filename}"
            file_path = os.path.join('uploads', system_filename)
            
            os.makedirs('uploads', exist_ok=True)
            with open(file_path, 'wb') as f:
                f.write(file_contents)

            # Create new file entry
            new_file = Files(
                owner_id=user_id,
                name=filename,
                path=file_path,
                uploaded_at=datetime.now(UTC),
                uuid=file_uuid or uuid.uuid4()
            )
            db.add(new_file)
            db.flush()
            
            # Create metadata entry
            file_metadata = FileMetadata(
                file_id=new_file.id,
                size=metadata['size'],
                format=metadata['format'],
                last_updated_at=datetime.now(UTC)
            )
            db.add(file_metadata)
            
            db.commit()
            logger.info(f"File {filename} uploaded successfully by user {user_id}")
            return jsonify({
                'message': 'File uploaded successfully',
                'uuid': str(new_file.uuid)
            }), 201

        except Exception as e:
            db.rollback()
            # Clean up file if it was created
            if 'file_path' in locals():
                try:
                    os.remove(file_path)
                except:
                    pass
            logger.error(f"Error uploading file {filename}: {str(e)}")
            return jsonify({'error': str(e)}), 500

def get_user_files(user_id: int) -> dict:
    """Get all files accessible to a user (owned and shared).

    Args:
        user_id (int): ID of the user requesting files

    Returns:
        dict: Response containing lists of owned and shared files
    """
    try:
        with get_session() as db:
            # Get files owned by the user
            owned_files = db.query(Files).filter_by(owner_id=user_id).all()
            owned_files_data = [{
                'uuid': str(file.uuid),
                'filename': file.name,
                'file_size': file.file_metadata.size if file.file_metadata else None,  
                'format': file.file_metadata.format if file.file_metadata else None,   
                'uploaded_at': file.uploaded_at.isoformat() if file.uploaded_at else None,
                'is_owner': True
            } for file in owned_files]

            # Get files shared with the user
            shared_permissions = db.query(FilePermissions).filter_by(user_id=user_id).all()
            shared_file_ids = [permission.file_id for permission in shared_permissions]
            shared_files = db.query(Files).filter(Files.id.in_(shared_file_ids)).all()

        shared_files_map = {file.id: file for file in shared_files}
        shared_files_data = []
        for permission in shared_permissions:
            file = shared_files_map.get(permission.file_id)
            if file:
                shared_files_data.append({
                    'uuid': str(file.uuid),
                    'filename': file.name,
                    'file_size': file.metadata.size if file.metadata else None,
                    'format': file.metadata.format if file.metadata else None,
                    'uploaded_at': file.uploaded_at.isoformat() if file.uploaded_at else None,
                    'is_owner': False
                })

        logger.info(f"User {user_id} retrieved their files successfully")
        return jsonify({
            'owned_files': owned_files_data,
            'shared_files': shared_files_data
        })

    except Exception as e:
        logger.error(f"Error retrieving files for user {user_id}: {str(e)}")
        return jsonify({'error': str(e)}), 500

def get_file_by_uuid(file_uuid: str, user_id: int) -> dict:
    """Get a specific file by UUID if user has access.

    Args:
        file_uuid (str): UUID of the requested file
        user_id (int): ID of the user requesting the file

    Returns:
        dict: Response containing file data and sharing keys if user is owner
    """
    try:
        with get_session() as db:
            # Find the file
            file = db.query(Files).filter_by(uuid=file_uuid).first()
            if not file:
                logger.warning(f"File with UUID {file_uuid} not found for user {user_id}")
                return jsonify({'error': 'File not found'}), 404

            # Check if user has access
            if file.owner_id != user_id:
                permission = db.query(FilePermissions).filter_by(
                    file_id=file.id,
                    user_id=user_id
                ).first()
                if not permission:
                    logger.warning(f"User {user_id} not authorized to access file {file_uuid}")
                    return jsonify({'error': 'Not authorized to access this file'}), 403

            # Read the encrypted file
            try:
                with open(file.path, 'rb') as f:
                    encrypted_file = f.read()
            except Exception as e:
                logger.error(f"Error reading file {file.path}: {str(e)}")
                return jsonify({'error': 'Error reading file'}), 500

            response_data = {
                'encrypted_file': base64.b64encode(encrypted_file).decode('utf-8')
            }

            # If user is owner, include all sharing keys
            if file.owner_id == user_id:
                permissions = db.query(FilePermissions).filter_by(file_id=file.id).all()
                response_data['encrypted_keys'] = {
                    perm.user_id: perm.encryption_key for perm in permissions
                }
            logger.info(f"User {user_id} retrieved file {file_uuid} successfully")
        return jsonify(response_data)

    except Exception as e:
        logger.error(f"Error retrieving file {file_uuid} for user {user_id}: {str(e)}")
        return jsonify({'error': str(e)}), 500

def delete_file_by_uuid(file_uuid: str, user_id: int) -> dict:
    """Delete a file if user is the owner.

    Args:
        file_uuid (str): UUID of the file to delete
        user_id (int): ID of the user requesting deletion

    Returns:
        dict: Response containing success message or error
    """
    db = None
    try:
        with get_session() as db:
            # Find the file
            file = db.query(Files).filter_by(uuid=file_uuid).first()
            if not file:
                logger.warning(f"File with UUID {file_uuid} not found for user {user_id}")
                return jsonify({'error': 'File not found'}), 404

            # Verify ownership
            if file.owner_id != user_id:
                logger.warning(f"User {user_id} not authorized to delete file {file_uuid}")
                return jsonify({'error': 'Not authorized to delete this file'}), 403

            # Delete the file from disk
            try:
                os.remove(file.path)
            except Exception as e:
                logger.error(f"Error deleting file {file.path}: {str(e)}")
                return jsonify({'error': 'Error deleting file from disk'}), 500

            # Delete from database
            db.delete(file)
            db.commit()
            logger.info(f"User {user_id} deleted file {file_uuid} successfully")
            return jsonify({'message': 'File deleted successfully'})
    except Exception as e:
        logger.error(f"Error deleting file {file_uuid} for user {user_id}: {str(e)}")
        if db is not None:
            db.rollback()
        return jsonify({'error': str(e)}), 500
