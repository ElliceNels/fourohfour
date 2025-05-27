"""
Some test explainations:
- The tests use pytest fixtures to create a mock database session and Flask app context.
- The `mocker` fixture from pytest-mock is used to patch (mock) functions and methods for testing LOGIC flow.
- Each test checks the response status and content based on different scenarios, such as valid/invalid credentials, existing users, etc.
- The tests cover both successful and error cases for each function (using parameterized tests, each set is run with the function).
"""


import pytest
from unittest.mock import MagicMock
from server.utils.auth import login, sign_up, change_password, delete_account, change_username
from server.models.tables import Users
from server.app import create_app

app = create_app()

CODE_BAD_REQUEST = 400
CODE_UNAUTHORIZED = 401
CODE_NOT_FOUND = 404
CODE_CONFLICT = 409
CODE_SUCCESS = 200
CODE_CREATED = 201


# Mock database fixture - simulates a database session
@pytest.fixture
def mock_db():
    return MagicMock()

# Gives access to Flask app context for testing
@pytest.fixture
def app_ctx():
    with app.app_context():
        yield
        # Test code then runs in this context

# Helper for context manager mock
def mock_session_ctx(mock_db):
    class Ctx:
        def __enter__(self):
            return mock_db
        def __exit__(self, exc_type, exc_val, exc_tb):
            pass
    return Ctx()

@pytest.mark.parametrize("username, password, expected_status", [
    ("valid_user", b"correct_password", CODE_SUCCESS),  # Success
    ("invalid_user", b"wrong_password", CODE_NOT_FOUND),  # User not found
    (None, b"password", CODE_BAD_REQUEST),  # Missing username
    ("user", None, CODE_BAD_REQUEST),  # Missing password
    ("user", b"wrong", CODE_UNAUTHORIZED)  # Invalid password
])
def test_login_cases(username, password, expected_status, mock_db, app_ctx, mocker):
    user = Users(username=username, password=b"correct_password") if expected_status in [CODE_SUCCESS, CODE_UNAUTHORIZED] else None
    mock_db.query().filter_by().first.return_value = user
    mocker.patch('server.utils.auth.get_session', return_value=mock_session_ctx(mock_db))
    response = login(username, password)
    assert response[1] == expected_status
    data = response[0].get_json()
    if expected_status == CODE_SUCCESS:
        assert "access_token" in data
    else:
        assert "error" in data

@pytest.mark.parametrize("username, password, public_key, salt, expected_status", [
    ("new_user", "secure_pass", b"pub_key", b"salt123", CODE_CREATED),  # Success
    ("existing_user", "secure_pass", b"pub_key", b"salt123", CODE_CONFLICT),  # Username exists
    (None, "pass", b"pk", b"salt", CODE_BAD_REQUEST),  # Missing username
    ("user", None, b"pk", b"salt", CODE_BAD_REQUEST),  # Missing password
    ("user", "pass", None, b"salt", CODE_BAD_REQUEST),  # Missing public_key
    ("user", "pass", b"pk", None, CODE_BAD_REQUEST),  # Missing salt
])
def test_sign_up_cases(username, password, public_key, salt, expected_status, mock_db, app_ctx, mocker):
    if expected_status == CODE_CONFLICT:
        mock_db.query().filter_by().first.side_effect = [Users(username=username), None]
    else:
        mock_db.query().filter_by().first.return_value = None
    mocker.patch('server.utils.auth.get_session', return_value=mock_session_ctx(mock_db))
    response = sign_up(username, password, public_key, salt)
    assert response[1] == expected_status
    data = response[0].get_json()
    if expected_status == CODE_CREATED:
        assert "access_token" in data
    else:
        assert "error" in data

@pytest.mark.parametrize(
    "username, old_password, new_password, token, user_exists, token_error, expected_status, expected_error",
    [
        # Success
        ("user1", b"old_pass", b"new_pass", 'token', True, None, CODE_SUCCESS, None),
        # User not found
        ("user2", b"wrong_pass", b"new_pass", 'token', False, None, CODE_NOT_FOUND, None),
        # New password same as old
        ("user3", b"same_pass", b"same_pass", 'token', True, None, CODE_BAD_REQUEST, None),
        # Missing required fields (username or token)
        (None, b"old_pass", b"new_pass", "token", False, None, CODE_NOT_FOUND, None),
        ("user4", "old_pass", b"new_pass", None, True, None, CODE_BAD_REQUEST, None),
        # Token error
        ("user5", b"old_pass", b"new_pass", 'token', True, {"response": "err", "status": CODE_UNAUTHORIZED}, CODE_UNAUTHORIZED, "err"),
    ]
)
def test_change_password_cases(
    username, old_password, new_password, token, user_exists, token_error, expected_status, expected_error,
    mock_db, app_ctx, mocker
):
    from server.utils.auth import change_password
    # Patch DB session
    if user_exists:
        user = Users(id=1, username=username, password=old_password)
        mock_db.query().filter_by().first.return_value = user
    else:
        mock_db.query().filter_by().first.return_value = None
    mocker.patch('server.utils.auth.get_session', return_value=mock_session_ctx(mock_db))
    # Patch get_user_id_from_token
    patch_args = dict()
    if token_error:
        patch_args['side_effect'] = lambda t: (None, token_error)
    else:
        patch_args['return_value'] = (1, None)
    mocker.patch('server.utils.auth.get_user_id_from_token', **patch_args)
    # Call function
    response = change_password(token, new_password)
    if token_error:
        assert response == token_error
    else:
        assert response[1] == expected_status
        data = response[0].get_json()
        if expected_status == CODE_SUCCESS:
            assert "message" in data
        else:
            assert "error" in data

@pytest.mark.parametrize("username, expected_status", [
    ("valid_user", CODE_SUCCESS),
    ("nonexistent_user", CODE_NOT_FOUND)
])
def test_delete_account(username, expected_status, mock_db, app_ctx, mocker):
    user = Users(username=username) if expected_status == CODE_SUCCESS else None
    mock_db.query().filter_by().first.return_value = user
    mocker.patch('server.utils.auth.get_session', return_value=mock_session_ctx(mock_db))
    response = delete_account(username)
    assert response[1] == expected_status
    data = response[0].get_json()
    if expected_status == CODE_SUCCESS:
        assert "message" in data
    else:
        assert "error" in data

@pytest.mark.parametrize("token, new_username, user_exists, token_error, username_conflict, same_username, expected_status", [
    (None, "new", True, None, False, False, CODE_BAD_REQUEST),
    ("token", None, True, None, False, False, CODE_BAD_REQUEST),
    ("token", "new", True, {"response": "err", "status": CODE_UNAUTHORIZED}, False, False, CODE_UNAUTHORIZED),
    ("token", "new", False, None, False, False, CODE_NOT_FOUND),
    ("token", "new", True, None, True, False, CODE_CONFLICT),
    ("token", "same", True, None, False, True, CODE_BAD_REQUEST),
    ("token", "unique", True, None, False, False, CODE_SUCCESS)
])
def test_change_username_cases(token, new_username, user_exists, token_error, username_conflict, same_username, expected_status, mock_db, app_ctx, mocker):
    user = Users(id=1, username="same") if user_exists else None
    mock_db.query().filter_by().first.side_effect = [user, Users(username=new_username) if username_conflict else None]
    patch_args = dict()
    if token_error:
        patch_args['side_effect'] = lambda t: (None, token_error)
    else:
        patch_args['return_value'] = (1, None)
    mocker.patch('server.utils.auth.get_session', return_value=mock_session_ctx(mock_db))
    mocker.patch('server.utils.auth.get_user_id_from_token', **patch_args)
    response = change_username(token, new_username)
    if token_error:
        assert response == token_error
    else:
        assert response[1] == expected_status
        data = response[0].get_json()
        if expected_status == CODE_SUCCESS:
            assert "message" in data
        else:
            assert "error" in data

@pytest.mark.parametrize(
    "token, token_error, user_exists, expected_status, expected_error, expected_username, expected_public_key",
    [
        # Invalid token
        ("badtoken", {"response": {"error": "Missing required fields"}, "status": CODE_BAD_REQUEST}, None, CODE_BAD_REQUEST, "Missing required fields", None, None),
        # Invalid user (user not found)
        ("token", None, False, CODE_NOT_FOUND, "User not found", None, None),
        # Success
        ("token", None, True, CODE_SUCCESS, None, "user", b"pk"),
    ]
)
def test_get_current_user_cases(token, token_error, user_exists, expected_status, expected_error, expected_username, expected_public_key, mock_db, app_ctx, mocker):
    from server.utils.auth import get_current_user

    # Patch get_current_token
    if token_error:
        mocker.patch('server.utils.auth.get_current_token', return_value=(None, token_error))
    else:
        mocker.patch('server.utils.auth.get_current_token', return_value=("token", None))

    # Patch get_user_id_from_token
    mocker.patch('server.utils.auth.get_user_id_from_token', return_value=(1, None))

    # Patch DB session and user
    if user_exists is None:
        # Don't patch DB for token error
        pass
    elif user_exists:
        user = Users(id=1, username="user", password="pw", public_key=b"pk", salt=b"salt", created_at="now", updated_at="now")
        mock_db.query().filter_by().first.return_value = user
        mocker.patch('server.utils.auth.get_session', return_value=mock_session_ctx(mock_db))
    else:
        mock_db.query().filter_by().first.return_value = None
        mocker.patch('server.utils.auth.get_session', return_value=mock_session_ctx(mock_db))

    resp, status = get_current_user(token)
    assert status == expected_status
    if expected_error:
        # If resp is a Flask Response, extract JSON
        if hasattr(resp, 'get_json'):
            assert resp.get_json()["error"] == expected_error
        else:
            assert resp.get("error") == expected_error
    else:
        assert resp["username"] == expected_username
        assert resp["public_key"] == expected_public_key