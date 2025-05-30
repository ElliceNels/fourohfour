import pytest
import uuid
import base64
from flask import Flask
from unittest.mock import MagicMock, patch, mock_open
from server.utils.file import upload_file_to_db, get_user_files, get_file_by_uuid, delete_file_by_uuid
from server.app import create_app

# HTTP status code constants
CODE_SUCCESS = 200
CODE_CREATED = 201
CODE_BAD_REQUEST = 400
CODE_FORBIDDEN = 403
CODE_NOT_FOUND = 404
CODE_CONFLICT = 409
CODE_SERVER_ERROR = 500

@pytest.fixture(scope="module")
def app_fixture():
    app = Flask(__name__)
    app.config.update(TESTING=True, JWT_SECRET_KEY="testsecret")
    return app

@pytest.fixture
def app_ctx(app_fixture):
    with app_fixture.app_context():
        yield

@pytest.fixture
def mock_db():
    return MagicMock()

def mock_session_ctx(mock_db):
    class Ctx:
        def __enter__(self):
            return mock_db
        def __exit__(self, exc_type, exc_val, exc_tb):
            pass
    return Ctx()

@pytest.mark.parametrize("user_id, file_present, uuid_provided, file_exists, is_owner, db_error, expected_status", [
    # Basic cases
    (1, True, None, False, False, False, CODE_CREATED),  # New file upload
    (1, False, None, False, False, False, CODE_BAD_REQUEST),  # No file provided
    
    # UUID update cases
    (1, True, str(uuid.uuid4()), True, True, False, CODE_CREATED),  # Update existing file (owner)
    (1, True, str(uuid.uuid4()), True, False, False, CODE_FORBIDDEN),  # Update existing file (not owner)
    (1, True, str(uuid.uuid4()), False, False, False, CODE_NOT_FOUND),  # Update non-existing file
    
    # Duplicate filename cases
    (1, True, None, True, False, False, CODE_CONFLICT),  # Duplicate filename
    
    # Error cases
    (1, True, None, False, False, True, CODE_SERVER_ERROR),  # DB error
])
def test_upload_file_to_db(user_id, file_present, uuid_provided, file_exists, is_owner, db_error, expected_status, mock_db, app_ctx, mocker):
    # Set up test data
    filename = "test.txt" if file_present else None
    file_contents_b64 = "dGVzdCBjb250ZW50" if file_present else None # Base64 for "test content"
    metadata = {'size': 123, 'format': 'txt'}
    test_uuid = uuid.UUID(uuid_provided) if uuid_provided else None

    # Mock existing file query
    existing_file = None
    if file_exists:
        existing_file = MagicMock()
        existing_file.owner_id = user_id if is_owner else user_id + 1
        existing_file.uuid = test_uuid
        existing_file.name = "test.txt"
        existing_file.path = "/tmp/test.txt"
        existing_file.file_metadata = MagicMock()
        existing_file.file_metadata.size = 123
        existing_file.file_metadata.format = 'txt'

    mock_db.query().filter_by().first.return_value = existing_file

    # Mock DB operations
    if db_error:
        mock_db.add.side_effect = Exception("DB error")
    else:
        mock_db.add.side_effect = None
        mock_db.flush.side_effect = None
        mock_db.commit.side_effect = None
        mock_db.rollback.side_effect = None
        def add_side_effect(obj):
            if hasattr(obj, 'id'):
                obj.id = 42
            if hasattr(obj, 'uuid'):
                obj.uuid = test_uuid if test_uuid else uuid.uuid4()
        mock_db.add.side_effect = add_side_effect

    # Mock file operations
    mocker.patch('os.makedirs')
    mocker.patch('os.remove')
    mocker.patch('builtins.open', mock_open())
    mocker.patch('base64.b64decode', return_value=b'test content')

    # Run test
    mocker.patch('server.utils.file.get_session', return_value=mock_session_ctx(mock_db))
    
    # Call with the new function signature
    response = upload_file_to_db(user_id, filename, file_contents_b64, metadata, test_uuid)
    
    # Handle both tuple and single return formats
    if isinstance(response, tuple):
        response_obj, status = response
        data = response_obj.get_json()
    else:
        status = 500
        data = response.get_json()
    
    # Assertions
    assert status == expected_status, f"Expected {expected_status}, got {status}. Response: {data}"
    
    if expected_status == CODE_CREATED:
        assert 'uuid' in data or 'message' in data
        if test_uuid and 'uuid' in data:
            assert data['uuid'] == str(test_uuid)
    elif expected_status == CODE_BAD_REQUEST:
        assert 'error' in data
    else:
        assert 'error' in data

@pytest.mark.parametrize("user_id, owned_files, shared_files, db_error, expected_status", [
    (1, [type('Obj', (), {'id': 1, 'uuid': uuid.uuid4(), 'name': 'a', 'file_metadata': type('Meta', (), {'size': 1, 'format': 'txt'})(), 'uploaded_at': None})()], [], False, CODE_SUCCESS),
    (2, [], [], True, CODE_SERVER_ERROR),
])
def test_get_user_files(user_id, owned_files, shared_files, db_error, expected_status, mock_db, app_ctx, mocker):
    if db_error:
        mocker.patch('server.utils.file.get_session', side_effect=Exception("DB error"))
    else:
        mock_db.query().filter_by().all.side_effect = [owned_files, shared_files]
        mock_db.query().filter().all.return_value = shared_files
        mocker.patch('server.utils.file.get_session', return_value=mock_session_ctx(mock_db))
    response = get_user_files(user_id)
    if isinstance(response, tuple):
        data, status = response
        assert status == expected_status
        if status == CODE_SERVER_ERROR:
            assert 'error' in data.get_json()
        else:
            data = data.get_json()
            assert 'owned_files' in data
            assert 'shared_files' in data
            if owned_files:
                assert 'uuid' in data['owned_files'][0]
    else:
        data = response.get_json()
        assert 'owned_files' in data
        assert 'shared_files' in data
        if owned_files:
            assert 'uuid' in data['owned_files'][0]

@pytest.mark.parametrize("file_uuid, user_id, file_found, owner, has_permission, file_read_error, db_error, expected_status", [
    (uuid.uuid4(), 1, True, True, True, False, False, CODE_SUCCESS),  # Owner, success
    (uuid.uuid4(), 2, True, False, True, False, False, CODE_SUCCESS),  # Shared, success
    (uuid.uuid4(), 3, True, False, False, False, False, CODE_FORBIDDEN),  # No permission
    (uuid.uuid4(), 4, False, False, False, False, False, CODE_NOT_FOUND),  # File not found
    (uuid.uuid4(), 5, True, True, True, True, False, CODE_SERVER_ERROR),  # File read error
    (uuid.uuid4(), 6, True, True, True, False, True, CODE_SERVER_ERROR),  # DB error
])
def test_get_file_by_uuid(file_uuid, user_id, file_found, owner, has_permission, file_read_error, db_error, expected_status, mock_db, app_ctx, mocker):
    if db_error:
        mocker.patch('server.utils.file.get_session', side_effect=Exception("DB error"))
    else:
        file_obj = MagicMock()
        file_obj.uuid = file_uuid
        file_obj.owner_id = user_id if owner else user_id + 100
        file_obj.name = "file.txt"
        file_obj.path = f"/tmp/{file_uuid}.txt"
        file_obj.metadata = MagicMock(size=123, format='txt')
        file_obj.uploaded_at = None

        # Set up the file query mock
        file_query = MagicMock()
        file_query.filter_by().first.return_value = file_obj if file_found else None
        
        # Set up the permissions query mock
        perm_query = MagicMock()
        if not file_found:
            perm_query.filter_by().first.return_value = None
        elif owner:
            perm_query.filter_by().all.return_value = [MagicMock(user_id=1, encryption_key='key')]
        elif has_permission:
            perm_query.filter_by().first.return_value = MagicMock()
        else:
            perm_query.filter_by().first.return_value = None

        # Make query() return different mocks based on the query
        def query_side_effect(*args, **kwargs):
            if args[0].__name__ == 'Files':
                return file_query
            return perm_query
        
        mock_db.query.side_effect = query_side_effect
        mocker.patch('server.utils.file.get_session', return_value=mock_session_ctx(mock_db))

        # Patch open
        if file_found and (owner or has_permission) and not file_read_error:
            m = mock_open(read_data=b"encrypted")
            mocker.patch("builtins.open", m)
        elif file_found and (owner or has_permission) and file_read_error:
            mocker.patch("builtins.open", side_effect=Exception("read error"))
    
    response = get_file_by_uuid(str(file_uuid), user_id)
    

    data, status = response
    assert status == expected_status
    if expected_status == CODE_SUCCESS:
        data = data.get_json()
        assert 'encrypted_file' in data
        if owner:
            assert 'encrypted_keys' in data
    else:
        assert 'error' in data.get_json()

@pytest.mark.parametrize("file_uuid, user_id, file_found, owner, file_delete_error, db_error, expected_status", [
    (uuid.uuid4(), 1, True, True, False, False, CODE_SUCCESS),  # Success
    (uuid.uuid4(), 2, True, False, False, False, CODE_FORBIDDEN),  # Not owner
    (uuid.uuid4(), 3, False, False, False, False, CODE_NOT_FOUND),  # File not found
    (uuid.uuid4(), 4, True, True, True, False, CODE_SERVER_ERROR),  # File delete error
    (uuid.uuid4(), 5, True, True, False, True, CODE_SERVER_ERROR),  # DB error
])
def test_delete_file_by_uuid(file_uuid, user_id, file_found, owner, file_delete_error, db_error, expected_status, mock_db, app_ctx, mocker):
    if db_error:
        mocker.patch('server.utils.file.get_session', side_effect=Exception("DB error"))
    else:
        file_obj = MagicMock()
        file_obj.uuid = file_uuid
        file_obj.owner_id = user_id if owner else user_id + 100
        file_obj.path = f"/tmp/{file_uuid}.txt"
        mock_db.query().filter_by().first.return_value = file_obj if file_found else None
        mocker.patch('server.utils.file.get_session', return_value=mock_session_ctx(mock_db))
        if file_found and owner and file_delete_error:
            mocker.patch("os.remove", side_effect=Exception("delete error"))
        elif file_found and owner:
            mocker.patch("os.remove", return_value=None)
    response = delete_file_by_uuid(str(file_uuid), user_id)
    if isinstance(response, tuple):
        data, status = response
        assert status == expected_status
        if status == CODE_SUCCESS:
            assert 'message' in data.get_json()
        else:
            assert 'error' in data.get_json()
    else:
        data = response.get_json()
        assert 'message' in data
