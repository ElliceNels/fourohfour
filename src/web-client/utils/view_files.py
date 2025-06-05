from session_manager import LoginSessionManager
from constants import GET_FILES
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
    response = LoginSessionManager.getInstance().get(GET_FILES)
    if response is None or response.status_code != 200:
        logger.error("Failed to fetch current user info")
        raise Exception("Failed to fetch current user info")

    file_info = response.json()

    init_owned_files = _remove_corrupted_files(file_info.get('owned_files'))
    init_shared_files = _remove_corrupted_files(file_info.get('shared_files'))

    # Process owned files
    owned_files = []
    for file in init_owned_files:
        if file.get("filename") and file.get("format"):
            full_filename = f"{file['filename']}.{file['format']}"
            # Convert file size to human readable format
            file['file_size'] = _format_file_size(file['file_size'])
            owned_files.append((file, full_filename))
        else:
            logger.warning(f"Missing filename or format for owned file: {file}")

    # Process shared files
    shared_files = []
    for file in init_shared_files:
        if file.get("filename") and file.get("format"):
            full_filename = f"{file['filename']}.{file['format']}"
            # Convert file size to human readable format
            file['file_size'] = _format_file_size(file['file_size'])
            shared_files.append((file, full_filename))
        else:
            logger.warning(f"Missing filename or format for shared file: {file}")

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
        