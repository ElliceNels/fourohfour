from datetime import datetime, UTC
from flask import jsonify
import os
import base64
from src.server.models.tables import Files, FilePermissions, FileMetadata
from src.server.utils.db_setup import get_session



def upload_file_to_db(user_id: int, file, file_path: str, metadata: dict) -> dict:
    """Upload a file to the database and disk storage.

    Args:
        user_id (int): ID of the user uploading the file
        file: The file object from request.files
        file_path (str): Path where the file will be stored
        metadata (dict): Dictionary containing file metadata (size, format)

    Returns:
        dict: Response containing success message and file ID or error message
    """
    with get_session() as db:
        try:
            # Create database entry
            new_file = Files(
                owner_id=user_id,
                name=file.filename,
                path=file_path,
                uploaded_at=datetime.now(UTC)
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
            return jsonify({
                'message': 'File uploaded successfully',
                'file_id': new_file.id
            }), 201

        except Exception as e:
            db.rollback()
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
                'id': file.id,
                'filename': file.name,
                'file_size': file.metadata.size if file.metadata else None,
                'format': file.metadata.format if file.metadata else None,
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
                    'id': file.id,
                    'filename': file.name,
                    'file_size': file.metadata.size if file.metadata else None,
                    'format': file.metadata.format if file.metadata else None,
                    'uploaded_at': file.uploaded_at.isoformat() if file.uploaded_at else None,
                    'is_owner': False
                })

        return jsonify({
            'owned_files': owned_files_data,
            'shared_files': shared_files_data
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

def get_file_by_id(file_id: int, user_id: int) -> dict:
    """Get a specific file by ID if user has access.

    Args:
        file_id (int): ID of the requested file
        user_id (int): ID of the user requesting the file

    Returns:
        dict: Response containing file data and sharing keys if user is owner
    """
    try:
        with get_session() as db:
            # Find the file
            file = db.query(Files).get(file_id)
            if not file:
                return jsonify({'error': 'File not found'}), 404

            # Check if user has access
            if file.owner_id != user_id:
                permission = db.query(FilePermissions).filter_by(
                    file_id=file_id,
                    user_id=user_id
                ).first()
                if not permission:
                    return jsonify({'error': 'Not authorized to access this file'}), 403

            # Read the encrypted file
            try:
                with open(file.path, 'rb') as f:
                    encrypted_file = f.read()
            except Exception as e:
                return jsonify({'error': 'Error reading file'}), 500

            response_data = {
                'encrypted_file': base64.b64encode(encrypted_file).decode('utf-8')
            }

            # If user is owner, include all sharing keys
            if file.owner_id == user_id:
                permissions = db.query(FilePermissions).filter_by(file_id=file_id).all()
                response_data['encrypted_keys'] = {
                    perm.user_id: perm.encryption_key for perm in permissions
                }

        return jsonify(response_data)

    except Exception as e:
        return jsonify({'error': str(e)}), 500

def delete_file_by_id(file_id: int, user_id: int) -> dict:
    """Delete a file if user is the owner.

    Args:
        file_id (int): ID of the file to delete
        user_id (int): ID of the user requesting deletion

    Returns:
        dict: Response containing success message or error
    """
    with get_session() as db:
        try:
            # Find the file
            file = db.query(Files).get(file_id)
            if not file:
                return jsonify({'error': 'File not found'}), 404

            # Verify ownership
            if file.owner_id != user_id:
                return jsonify({'error': 'Not authorized to delete this file'}), 403

            # Delete the file from disk
            try:
                os.remove(file.path)
            except Exception as e:
                return jsonify({'error': 'Error deleting file from disk'}), 500

            # Delete from database
            db.delete(file)
            db.commit()

            return jsonify({'message': 'File deleted successfully'})

        except Exception as e:
            db.rollback()
            return jsonify({'error': str(e)}), 500
