import base64
from flask import Blueprint, jsonify, request
from ..models.tables import Files, FilePermissions, Users, FileMetadata  
from ..utils.auth import get_current_user  # Assuming we have this utility for now. Spoiler, we don't
from werkzeug.utils import secure_filename
import os
from datetime import datetime, UTC

files_bp = Blueprint('files', __name__, url_prefix='/api/files')

@files_bp.route('/upload', methods=['POST'])
def upload_file():
    """
    Upload a new file
    Expects:
    - encrypted_file: The encrypted file data
    - size: File size in bytes
    - format: File format/extension
    """
    if 'encrypted_file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    try:
        # Get the current user from the request (assuming we have authentication middleware)
        current_user = get_current_user()
        
        # Save the file to disk (assuming we have a configured upload directory)
        file = request.files['encrypted_file']
        sanitized_filename = secure_filename(file.filename)
        filename = f"{current_user.id}_{sanitized_filename}"  # Prefix with user ID
        file_path = os.path.join('uploads', filename)  # Assuming we have an 'uploads' directory
        file.save(file_path)

        # Create database entry
        new_file = Files(
            owner_id=current_user.id,
            name=file.filename,
            path=file_path,
            uploaded_at=datetime.now(UTC)
        )
        db.session.add(new_file)
        db.session.flush() #so new file record is generated before we reference it below in metadata.
        
        # Create metadata entry using data from request
        file_metadata = FileMetadata(
            file_id=new_file.id,
            size=request.metadata['size'],
            format=request.metadata['format'],
            last_updated_at=datetime.now(UTC)
        )
        db.session.add(file_metadata)
        
        db.session.commit()
        db.session.close()

        return jsonify({
            'message': 'File uploaded successfully',
            'file_id': new_file.id
        }), 201

    except Exception as e:
        # Clean up file if database operation fails
        if 'file_path' in locals():
            try:
                os.remove(file_path)
            except:
                pass
        db.session.rollback()
        db.session.close()
        return jsonify({'error': str(e)}), 500

@files_bp.route('/', methods=['GET'])
def list_files():
    """
    List all files for the authenticated user, both in the file database and the filePermission database
    Returns:
    - files: A list of encrypted files
    - keys: A list of encrypted keys
    """
    try:
        current_user = get_current_user()
        
        # Get files owned by the user
        owned_files = Files.query.filter_by(owner_id=current_user.id).all()
        owned_files_data = [{
            'id': file.id,
            'filename': file.name,
            'file_size': file.metadata.size if file.metadata else None,
            'is_owner': True,
            'encrypted_file': file.path
        } for file in owned_files]

        # Get files shared with the user
        shared_permissions = FilePermissions.query.filter_by(user_id=current_user.id).all()
        shared_file_ids = [permission.file_id for permission in shared_permissions]
        shared_files = Files.query.filter(Files.id.in_(shared_file_ids)).all()
        shared_files_map = {file.id: file for file in shared_files}
        shared_files_data = []
        for permission in shared_permissions:
            file = shared_files_map.get(permission.file_id)
            if file:  # File might have been deleted
                shared_files_data.append({
                    'id': file.id,
                    'filename': file.name,
                    'file_size': file.metadata.size if file.metadata else None,
                    'is_owner': False,
                    'encrypted_file': file.path,
                    'encrypted_key': permission.encryption_key
                })

        db.session.close()
        return jsonify({
            'files': owned_files_data + shared_files_data
        })

    except Exception as e:
        db.session.close()
        return jsonify({'error': str(e)}), 500

@files_bp.route('/<file_id>', methods=['GET'])
def get_file(file_id):
    """
    Get a specific file by ID
    Expects:
    - file_id: The ID of the file
    Returns:
    - encrypted_file: The encrypted file data
    - encrypted_keys: The encrypted keys for sharing
    """
    try:
        # Get the current user from the request (assuming we have authentication middleware)
        current_user = get_current_user()
        
        # Find the file
        file = Files.query.get(file_id)
        if not file:
            db.session.close()
            return jsonify({'error': 'File not found'}), 404

        # Check if user has access
        if file.owner_id != current_user.id:
            # Check if file is shared with user
            permission = FilePermissions.query.filter_by(
                file_id=file_id,
                user_id=current_user.id
            ).first()
            if not permission:
                db.session.close()
                return jsonify({'error': 'Not authorized to access this file'}), 403

        # Read the encrypted file
        try:
            with open(file.path, 'rb') as f:
                encrypted_file = f.read()
        except Exception as e:
            db.session.close()
            return jsonify({'error': 'Error reading file'}), 500

        response_data = {
            'encrypted_file': base64.b64encode(encrypted_file).decode('utf-8')
        }

        # If user is owner, include all sharing keys
        if file.owner_id == current_user.id:
            permissions = FilePermissions.query.filter_by(file_id=file_id).all()
            response_data['encrypted_keys'] = {
                perm.user_id: perm.encryption_key for perm in permissions
            }

        db.session.close()
        return jsonify(response_data)

    except Exception as e:
        db.session.close()
        return jsonify({'error': str(e)}), 500

@files_bp.route('/<file_id>', methods=['DELETE'])
def delete_file(file_id):
    """
    Delete a specific file by ID
    Expects:
    - file_id: The ID of the file
    """
    try:
        current_user = get_current_user()
        
        # Find the file
        file = Files.query.get(file_id)
        if not file:
            db.session.close()
            return jsonify({'error': 'File not found'}), 404

        # Verify ownership
        if file.owner_id != current_user.id:
            db.session.close()
            return jsonify({'error': 'Not authorized to delete this file'}), 403

        # Delete the file from disk
        try:
            os.remove(file.path)
        except Exception as e:
            db.session.close()
            return jsonify({'error': 'Error deleting file from disk'}), 500

        # Delete from database (assuming we have cascade delete set up for FilePermission)
        db.session.delete(file)
        db.session.commit()
        db.session.close()

        return jsonify({'message': 'File deleted successfully'})

    except Exception as e:
        db.session.rollback()
        db.session.close()
        return jsonify({'error': str(e)}), 500