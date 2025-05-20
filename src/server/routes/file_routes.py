from flask import Blueprint, jsonify, request

files_bp = Blueprint('files', __name__, url_prefix='/api/files')

@files_bp.route('/upload', methods=['POST'])
def upload_file():
    """
    Upload a new file
    Expects:
    - encrypted_file: The encrypted file data
    """
    # TODO: Store the file on the server
    #TODO Add an entry to the file database, inlcuding file location etc
    return 

@files_bp.route('/', methods=['GET'])
def list_files():
    """
    List all files for the authenticated user, both in the file database and the filePermission database
    Returns:
    - files: A list of encrypted files
    -keys: A list of encrypted keys
    """
    # TODO: Query database for user's files
    # TODO: Find all files relating to user, both in the file database and the filePermission database
    # TODO: Check if the user and file have a corresponding entry in the filePermission database, or are the owner
    # TODO: If owner, send only encryted file
    # TODO: If shared, send both encrypted file and encrypted key
    return


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
    # TODO: Get user ID from authentication
    # TODO: Find the file in the database
    # TODO  : Check if the user and file have a correspoinding entry in the filePermission database
    # TODO: Return file and key from database
    return 

# Delete a specific file
@files_bp.route('/<file_id>', methods=['DELETE'])
def delete_file(file_id):
    """
    Delete a specific file by ID
    Expects:
    - file_id: The ID of the file
    """
    # TODO: Get user ID from authentication
    # TODO: Find file in the database
    # TODO: Verify if the user is the owner of the file
    # TODO: Delete the file. FilePermissions should cascade delete. 

    return jsonify({"message": "File deleted successfully"}), 200 