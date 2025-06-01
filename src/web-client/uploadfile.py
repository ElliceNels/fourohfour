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