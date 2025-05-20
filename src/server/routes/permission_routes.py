from flask import Blueprint, jsonify, request

permission_bp = Blueprint('permissions', __name__, url_prefix='/api/permissions')

@permission_bp.route('/public_key', methods=['GET'])
def get_public_key():
    """
    Get the public key of a user
    Expects:
    - user_id: The ID of the user
    """
    #TODO : Look up the user_id in the database, return their public key
    return 

@permission_bp.route('/add', methods=['POST'])
def add_permission():
    """
    Adds a permission to a file
    Expects:
    - file_id: The ID of the file
    - user_id: The ID of the user
    - key_for_recipient: The symmetric file key encrypted with the user_id public key
    """
    #TODO: Check if the user making the request is the owner of the file
    #TODO : Check if the file_id and user_id exist
    #TODO: Add a filePermission entry to the database

    return

@permission_bp.route('/remove', methods=['POST'])
def remove_permission():
    """
    Removes a permission from a file
    Expects:
    - file_id: The ID of the file
    - user_id: The ID of the user
    """
    #TODO: Check if the user making the request is the owner of the file
    #TODO check if the file_id and user_id exist
    #TODO: Remove the filePermissoin entry from the database
    return