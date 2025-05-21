from flask import Blueprint, jsonify, request
from ..models import File, FilePermission  # Assuming we have these models
from ..utils.auth import get_current_user  # Assuming we have this utility
import os  # Assuming we need this for file operations

files_bp = Blueprint('files', __name__, url_prefix='/api/files')

@files_bp.route('/upload', methods=['POST'])
def upload_file():
    """
    Upload a new file
    Expects:
    - encrypted_file: The encrypted file data
    """
    if 'encrypted_file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    try:
        # Get the current user from the request (assuming we have authentication middleware)
        current_user = get_current_user()
        
        # Save the file to disk (assuming we have a configured upload directory)
        file = request.files['encrypted_file']
        filename = f"{current_user.id}_{file.filename}"  # Assuming we want to prefix with user ID
        file_path = os.path.join('uploads', filename)  # Assuming we have an 'uploads' directory
        file.save(file_path)

        # Create database entry
        new_file = File(
            owner_id=current_user.id,
            filename=file.filename,
            file_path=file_path,
            file_size=os.path.getsize(file_path)
        )
        db.session.add(new_file)
        db.session.commit()

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
        # Get the current user from the request (assuming we have authentication middleware)
        current_user = get_current_user()
        
        # Get files owned by the user
        owned_files = File.query.filter_by(owner_id=current_user.id).all()
        owned_files_data = [{
            'id': file.id,
            'filename': file.filename,
            'file_size': file.file_size,
            'is_owner': True,
            'encrypted_file': file.file_path  # Assuming we store the path to the encrypted file
        } for file in owned_files]

        # Get files shared with the user
        shared_permissions = FilePermission.query.filter_by(user_id=current_user.id).all()
        shared_files_data = []
        for permission in shared_permissions:
            file = File.query.get(permission.file_id)
            if file:  # File might have been deleted
                shared_files_data.append({
                    'id': file.id,
                    'filename': file.filename,
                    'file_size': file.file_size,
                    'is_owner': False,
                    'encrypted_file': file.file_path,
                    'encrypted_key': permission.encrypted_key
                })

        return jsonify({
            'files': owned_files_data + shared_files_data
        })

    except Exception as e:
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
        file = File.query.get(file_id)
        if not file:
            return jsonify({'error': 'File not found'}), 404

        # Check if user has access
        if file.owner_id != current_user.id:
            # Check if file is shared with user
            permission = FilePermission.query.filter_by(
                file_id=file_id,
                user_id=current_user.id
            ).first()
            if not permission:
                return jsonify({'error': 'Not authorized to access this file'}), 403

        # Read the encrypted file
        try:
            with open(file.file_path, 'rb') as f:
                encrypted_file = f.read()
        except Exception as e:
            return jsonify({'error': 'Error reading file'}), 500

        response_data = {
            'encrypted_file': encrypted_file
        }

        # If user is owner, include all sharing keys
        if file.owner_id == current_user.id:
            permissions = FilePermission.query.filter_by(file_id=file_id).all()
            response_data['encrypted_keys'] = {
                perm.user_id: perm.encrypted_key for perm in permissions
            }

        return jsonify(response_data)

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@files_bp.route('/<file_id>', methods=['DELETE'])
def delete_file(file_id):
    """
    Delete a specific file by ID
    Expects:
    - file_id: The ID of the file
    """
    try:
        # Get the current user from the request (assuming we have authentication middleware)
        current_user = get_current_user()
        
        # Find the file
        file = File.query.get(file_id)
        if not file:
            return jsonify({'error': 'File not found'}), 404

        # Verify ownership
        if file.owner_id != current_user.id:
            return jsonify({'error': 'Not authorized to delete this file'}), 403

        # Delete the file from disk
        try:
            os.remove(file.file_path)
        except Exception as e:
            return jsonify({'error': 'Error deleting file from disk'}), 500

        # Delete from database (assuming we have cascade delete set up for FilePermission)
        db.session.delete(file)
        db.session.commit()

        return jsonify({'message': 'File deleted successfully'})

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500