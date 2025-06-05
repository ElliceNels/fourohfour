from utils.auth.session_manager import LoginSessionManager
from constants import FILES_ENDPOINT
import logging

logger = logging.getLogger(__name__)

def _format_file_size(bytes_size):
    """Convert bytes to human readable format (bytes, KB, or MB)."""
    try:
        bytes_size = float(bytes_size)
        if bytes_size < 1024:  # Less than 1 KB
            return f"{bytes_size:.1f} bytes"
        elif bytes_size < 1024 * 1024:  # Less than 1 MB
            kb_size = bytes_size / 1024
            return f"{kb_size:.1f} KB"
        else:  # MB or larger
            mb_size = bytes_size / (1024 * 1024)
            return f"{mb_size:.1f} MB"
    except (TypeError, ValueError):
        return "0 bytes"

def my_files():
    """Fetch files owned/shared with the user."""
    response = LoginSessionManager.getInstance().get(FILES_ENDPOINT)
    if response is None or response.status_code != 200:
        logger.error("Failed to fetch current user info")
        raise Exception("Failed to fetch current user info")

    file_info = response.json()

    init_owned_files = _remove_corrupted_files(file_info.get('owned_files'))
    init_shared_files = _remove_corrupted_files(file_info.get('shared_files'))    # Process owned files
    owned_files = []
    for file in init_owned_files:
        if file.get("filename"):
            # Use the filename directly since it already includes the extension
            # The 'format' field contains the MIME type, not the file extension
            full_filename = file['filename']
            # Convert file size to human readable format
            file['file_size'] = _format_file_size(file['file_size'])
            owned_files.append((file, full_filename))
        else:
            logger.warning(f"Missing filename for owned file: {file}")    # Process shared files
    shared_files = []
    for file in init_shared_files:
        if file.get("filename"):
            # Use the filename directly since it already includes the extension
            # The 'format' field contains the MIME type, not the file extension
            full_filename = file['filename']
            # Convert file size to human readable format
            file['file_size'] = _format_file_size(file['file_size'])
            shared_files.append((file, full_filename))
        else:
            logger.warning(f"Missing filename for shared file: {file}")

    return owned_files, shared_files

def _remove_corrupted_files(files):
    """Remove files with missing or corrupted data."""
    valid_files = []
    for file in files:
        if not file.get("filename") or not file.get("format") or not file.get("file_size") or not file.get("uploaded_at"):
            logger.warning(f"Corrupted file data found: {file}")
            continue
        valid_files.append(file)
    return valid_files
        
import os

def validate_file_size(file_size: int, max_size_mb: int = 10) -> tuple[bool, str]:
    """
    Validate if the file size is within acceptable limits.

    Args:
        file_size (int): Size of the file in bytes
        max_size_mb (int): Maximum allowed file size in megabytes. Defaults to 10MB.

    Returns:
        tuple[bool, str]: A tuple containing:
            - bool: True if file size is valid, False otherwise
            - str: Error message if invalid, empty string if valid
    """
    try:
        max_size_bytes = max_size_mb * 1024 * 1024  # Convert MB to bytes
        if file_size > max_size_bytes:
            return False, f"File size exceeds the maximum limit of {max_size_mb}MB"
        if file_size == 0:
            return False, "File is empty"
        return True, ""
    except Exception as e:
        return False, f"Error validating file size: {str(e)}"

def validate_file_type(file_name: str, allowed_extensions: set = None) -> tuple[bool, str]:
    """
    Validate if the file type is allowed.

    Args:
        file_name (str): Name of the file
        allowed_extensions (set): Set of allowed file extensions. Defaults to common safe extensions.

    Returns:
        tuple[bool, str]: A tuple containing:
            - bool: True if file type is valid, False otherwise
            - str: Error message if invalid, empty string if valid
    """
    try:
        if allowed_extensions is None:
            allowed_extensions = {
                '.txt', '.pdf', '.doc', '.docx', '.xls', '.xlsx',
                '.jpg', '.jpeg', '.png', '.gif', '.zip', '.rar'
            }

        file_extension = os.path.splitext(file_name)[1].lower()
        if not file_extension:
            return False, "File has no extension"
        if file_extension not in allowed_extensions:
            return False, f"File type {file_extension} is not allowed"
        return True, ""
    except Exception as e:
        return False, f"Error validating file type: {str(e)}"