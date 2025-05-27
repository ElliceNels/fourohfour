import pytest
from unittest.mock import MagicMock, patch, mock_open
from server.utils.file import upload_file_to_db, get_user_files, get_file_by_id, delete_file_by_id
from server.app import create_app

app = create_app()

# HTTP status code constants
CODE_SUCCESS = 200
CODE_CREATED = 201
CODE_BAD_REQUEST = 400
CODE_FORBIDDEN = 403
CODE_NOT_FOUND = 404
CODE_SERVER_ERROR = 500

@pytest.fixture
def app_ctx():
    with app.app_context():
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

@pytest.mark.parametrize("user_id, file_present, db_error, expected_status", [
    (1, True, False, CODE_CREATED),  # Success
    (1, False, False, CODE_BAD_REQUEST),  # No file provided
    (1, True, True, CODE_SERVER_ERROR),  # DB error
])
def test_upload_file_to_db(user_id, file_present, db_error, expected_status, mock_db, app_ctx, mocker):
    class DummyFile:
        filename = "test.txt"
    file = DummyFile() if file_present else None
    file_path = "/tmp/test.txt"
    metadata = {'size': 123, 'format': 'txt'}
    if db_error:
        mock_db.add.side_effect = Exception("DB error")
    else:
        mock_db.add.side_effect = None
        mock_db.flush.side_effect = None
        mock_db.commit.side_effect = None
        mock_db.rollback.side_effect = None
        # Simulate new_file.id
        def add_side_effect(obj):
            if hasattr(obj, 'id'):
                obj.id = 42
        mock_db.add.side_effect = add_side_effect
    mocker.patch('server.utils.file.get_session', return_value=mock_session_ctx(mock_db))
    response, status = upload_file_to_db(user_id, file, file_path, metadata)
    assert status == expected_status
    data = response.get_json()
    if expected_status == CODE_CREATED:
        assert 'file_id' in data
    else:
        assert 'error' in data

@pytest.mark.parametrize("user_id, owned_files, shared_files, db_error, expected_status", [
    (1, [type('Obj', (), {'id': 1, 'name': 'a', 'metadata': type('Meta', (), {'size': 1, 'format': 'txt'})(), 'uploaded_at': None})()], [], False, CODE_SUCCESS),
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
    else:
        data = response.get_json()
        assert 'owned_files' in data
        assert 'shared_files' in data

@pytest.mark.parametrize("file_id, user_id, file_found, owner, has_permission, file_read_error, db_error, expected_status", [
    (1, 1, True, True, True, False, False, CODE_SUCCESS),  # Owner, success
    (2, 2, True, False, True, False, False, CODE_SUCCESS),  # Shared, success
    (3, 3, True, False, False, False, False, CODE_FORBIDDEN),  # No permission
    (4, 4, False, False, False, False, False, CODE_NOT_FOUND),  # File not found
    (5, 5, True, True, True, True, False, CODE_SERVER_ERROR),  # File read error
    (6, 6, True, True, True, False, True, CODE_SERVER_ERROR),  # DB error
])
def test_get_file_by_id(file_id, user_id, file_found, owner, has_permission, file_read_error, db_error, expected_status, mock_db, app_ctx, mocker):
    if db_error:
        mocker.patch('server.utils.file.get_session', side_effect=Exception("DB error"))
    else:
        file_obj = MagicMock()
        file_obj.id = file_id
        file_obj.owner_id = user_id if owner else user_id + 100
        file_obj.name = "file.txt"
        file_obj.path = f"/tmp/{file_id}.txt"
        file_obj.metadata = MagicMock(size=123, format='txt')
        file_obj.uploaded_at = None
        # .get()
        mock_db.query().get.return_value = file_obj if file_found else None
        # Permissions
        if not file_found:
            pass
        elif owner:
            mock_db.query().filter_by().all.return_value = [MagicMock(user_id=1, encryption_key='key')]  # owner gets keys
        elif has_permission:
            mock_db.query().filter_by().first.return_value = MagicMock()
        else:
            mock_db.query().filter_by().first.return_value = None
        mocker.patch('server.utils.file.get_session', return_value=mock_session_ctx(mock_db))
        # Patch open
        if file_found and (owner or has_permission) and not file_read_error:
            m = mock_open(read_data=b"encrypted")
            mocker.patch("builtins.open", m)
        elif file_found and (owner or has_permission) and file_read_error:
            mocker.patch("builtins.open", side_effect=Exception("read error"))
    response = get_file_by_id(file_id, user_id)
    if expected_status == CODE_SUCCESS:
        data = response.get_json()
        assert 'encrypted_file' in data
        if owner:
            assert 'encrypted_keys' in data
    else:
        if db_error:
            assert response[1] == CODE_SERVER_ERROR
        else:
            assert response[1] == expected_status
        assert 'error' in response[0].get_json()

@pytest.mark.parametrize("file_id, user_id, file_found, owner, file_delete_error, db_error, expected_status", [
    (1, 1, True, True, False, False, CODE_SUCCESS),  # Success
    (2, 2, True, False, False, False, CODE_FORBIDDEN),  # Not owner
    (3, 3, False, False, False, False, CODE_NOT_FOUND),  # File not found
    (4, 4, True, True, True, False, CODE_SERVER_ERROR),  # File delete error
    (5, 5, True, True, False, True, CODE_SERVER_ERROR),  # DB error
])
def test_delete_file_by_id(file_id, user_id, file_found, owner, file_delete_error, db_error, expected_status, mock_db, app_ctx, mocker):
    if db_error:
        mocker.patch('server.utils.file.get_session', side_effect=Exception("DB error"))
    else:
        file_obj = MagicMock()
        file_obj.id = file_id
        file_obj.owner_id = user_id if owner else user_id + 100
        file_obj.path = f"/tmp/{file_id}.txt"
        mock_db.query().get.return_value = file_obj if file_found else None
        mocker.patch('server.utils.file.get_session', return_value=mock_session_ctx(mock_db))
        if file_found and owner and file_delete_error:
            mocker.patch("os.remove", side_effect=Exception("delete error"))
        elif file_found and owner:
            mocker.patch("os.remove", return_value=None)
    response = delete_file_by_id(file_id, user_id)
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
