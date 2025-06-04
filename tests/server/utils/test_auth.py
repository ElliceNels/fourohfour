"""
Some test explainations:
- The tests use pytest fixtures to create a mock database session and Flask app context.
- The `mocker` fixture from pytest-mock is used to patch (mock) functions and methods for testing LOGIC flow.
- Each test checks the response status and content based on different scenarios, such as valid/invalid credentials, existing users, etc.
- The tests cover both successful and error cases for each function (using parameterized tests, each set is run with the function).
"""


import pytest
from flask import Flask
from unittest.mock import MagicMock
from server.utils.auth import (
    login, sign_up, change_password, delete_account, change_username, 
    hash_password, get_count_otpk, update_spk
)
from server.models.tables import Users, OTPK
from server.app import create_app
from server.utils.jwt import JWTError
from server.config import config
import base64
from datetime import datetime, timedelta, timezone

app = create_app()

CODE_BAD_REQUEST = 400
CODE_UNAUTHORIZED = 401
CODE_NOT_FOUND = 404
CODE_CONFLICT = 409
CODE_SUCCESS = 200
CODE_CREATED = 201
CODE_FORBIDDEN = 403

@pytest.fixture(scope="module")
def app_fixture():
    app = Flask(__name__)
    app.config.update(TESTING=True, JWT_SECRET_KEY="testsecret")
    return app

@pytest.fixture
def app_ctx(app_fixture):
    with app_fixture.app_context():
        yield
        # Test code then runs in this context

# Mock database fixture - simulates a database session
@pytest.fixture
def mock_db():
    return MagicMock()

# Helper for context manager mock
def mock_session_ctx(mock_db):
    class Ctx:
        def __enter__(self):
            return mock_db
        def __exit__(self, exc_type, exc_val, exc_tb):
            pass
    return Ctx()

@pytest.mark.parametrize("username, password, expected_status", [
    ("valid_user", "correct_password", CODE_SUCCESS),  # Success
    ("invalid_user", "wrong_password", CODE_NOT_FOUND),  # User not found
    (None, "password", CODE_BAD_REQUEST),  # Missing username
    ("user", None, CODE_BAD_REQUEST),  # Missing password
    ("user", "wrong", CODE_UNAUTHORIZED)  # Invalid password
])
def test_login_cases(username, password, expected_status, mock_db, app_ctx, mocker):
    salt = b"salt"
    if expected_status in [CODE_SUCCESS, CODE_UNAUTHORIZED]:
        current_time = datetime.now(timezone.utc)
        user = Users(
            id=1,  # Add user ID
            username=username, 
            password=hash_password("correct_password"), 
            salt=salt,
            spk="valid_spk",
            spk_signature="valid_signature",
            spk_updated_at=current_time,  # Add spk_updated_at
            updated_at=current_time
        )
        mock_db.query().filter_by().first.return_value = user
        # Mock OTPK count for successful login
        if expected_status == CODE_SUCCESS:
            mock_db.query().filter_by().count.return_value = 10  # Ensure enough OTPKs
    else:
        mock_db.query().filter_by().first.return_value = None
    mocker.patch('server.utils.auth.get_session', return_value=mock_session_ctx(mock_db))
    response = login(username, password)
    assert response[1] == expected_status
    data = response[0].get_json()
    if expected_status == CODE_SUCCESS:
        assert "access_token" in data
    else:
        assert "error" in data

@pytest.mark.parametrize("username, password, spk_age_days, otpk_count, expected_status, expected_error", [
    ("valid_user", "correct_password", 0, 10, CODE_SUCCESS, None),  # Fresh SPK, sufficient OTPKs
    ("valid_user", "correct_password", 6, 10, CODE_SUCCESS, None),  # SPK within limit, sufficient OTPKs
    ("valid_user", "correct_password", 7, 10, CODE_FORBIDDEN, "SPK is too old"),  # SPK too old
    ("valid_user", "correct_password", 0, 4, CODE_FORBIDDEN, "Not enough unused OTPKs"),  # Not enough OTPKs
    ("valid_user", "correct_password", 6, 4, CODE_FORBIDDEN, "Not enough unused OTPKs"),  # SPK ok but not enough OTPKs
])
def test_login_spk_otpk_validation(username, password, spk_age_days, otpk_count, expected_status, expected_error, mock_db, app_ctx, mocker):
    """Test login validation of SPK age and OTPK count."""
    spk_max_age = config.spk.max_age_days
    min_otpk_count = config.otpk.min_unused_count
    
    # Create user with SPK updated at specific time
    salt = b"salt"
    current_time = datetime.now(timezone.utc)
    user = Users(
        id=1,  # Add user ID
        username=username,
        password=hash_password("correct_password"),
        salt=salt,
        spk="valid_spk",
        spk_signature="valid_signature",
        spk_updated_at=current_time - timedelta(days=spk_age_days),  # Set spk_updated_at based on age
        updated_at=current_time
    )
    
    # Mock database responses
    mock_db.query().filter_by().first.return_value = user
    # Mock OTPK count based on test parameters
    mock_db.query().filter_by().count.return_value = otpk_count
    
    # Patch database session
    mocker.patch('server.utils.auth.get_session', return_value=mock_session_ctx(mock_db))
    
    # Call login function
    response = login(username, password)
    
    # Verify response
    assert response[1] == expected_status
    data = response[0].get_json()
    
    if expected_status == CODE_SUCCESS:
        assert "access_token" in data
    else:
        assert "error" in data
        if expected_error:
            assert expected_error in data["error"]
            
    # Verify that the validation was actually performed
    if spk_age_days > spk_max_age:
        assert "SPK is too old" in data["error"]
    if otpk_count < min_otpk_count:
        assert "Not enough unused OTPKs" in data["error"]

@pytest.mark.parametrize("username, password, public_key, spk, spk_signature, salt, expected_status", [
    ("new_user", "secure_pass", "cHViX2tleQ==", "c3BrX2tleQ==", "c2lnbmF0dXJl", b"salt123", CODE_CREATED),  # Success - base64 values
    ("existing_user", "secure_pass", "cHViX2tleQ==", "c3BrX2tleQ==", "c2lnbmF0dXJl", b"salt123", CODE_CONFLICT),  # Username exists
    (None, "pass", "cGs=", "c3BrX2tleQ==", "c2lnbmF0dXJl", b"salt", CODE_BAD_REQUEST),  # Missing username
    ("user", None, "cGs=", "c3BrX2tleQ==", "c2lnbmF0dXJl", b"salt", CODE_BAD_REQUEST),  # Missing password
    ("user", "pass", None, "c3BrX2tleQ==", "c2lnbmF0dXJl", b"salt", CODE_BAD_REQUEST),  # Missing public_key
    ("user", "pass", "cGs=", None, "c2lnbmF0dXJl", b"salt", CODE_BAD_REQUEST),  # Missing spk
    ("user", "pass", "cGs=", "c3BrX2tleQ==", None, b"salt", CODE_BAD_REQUEST),  # Missing spk_signature
    ("user", "pass", "cGs=", "c3BrX2tleQ==", "c2lnbmF0dXJl", None, CODE_BAD_REQUEST),  # Missing salt
    ("user", "pass", "invalid_base64!", "c3BrX2tleQ==", "c2lnbmF0dXJl", b"salt", CODE_BAD_REQUEST),  # Invalid base64 public key
    ("user", "pass", "cGs=", "invalid_base64!", "c2lnbmF0dXJl", b"salt", CODE_BAD_REQUEST),  # Invalid base64 spk
    ("user", "pass", "cGs=", "c3BrX2tleQ==", "invalid_base64!", b"salt", CODE_BAD_REQUEST),  # Invalid base64 spk_signature
])
def test_sign_up_cases(username, password, public_key, spk, spk_signature, salt, expected_status, mock_db, app_ctx, mocker):
    if expected_status == CODE_CONFLICT:
        mock_db.query().filter_by().first.side_effect = [Users(username=username), None]
    else:
        mock_db.query().filter_by().first.return_value = None
    mocker.patch('server.utils.auth.get_session', return_value=mock_session_ctx(mock_db))
    response = sign_up(username, password, public_key, spk, spk_signature, salt)
    assert response[1] == expected_status
    data = response[0].get_json()
    if expected_status == CODE_CREATED:
        assert "access_token" in data
    else:
        assert "error" in data

@pytest.mark.parametrize(
    "username, old_password, new_password, salt, token, user_exists, token_error, expected_status, expected_error",
    [
        # Success
        ("user1", "old_pass", "new_pass", b"salt2", 'token', True, None, CODE_SUCCESS, None),
        # User not found
        ("user2", "wrong_pass", "new_pass", b"salt2", 'token', False, None, CODE_NOT_FOUND, None),
        # New password same as old
        ("user3", "same_pass", "same_pass", b"salt3", 'token', True, None, CODE_BAD_REQUEST, None),
        # Missing required fields (username or token)
        (None, "old_pass", "new_pass", b"salt4", "token", False, None, CODE_NOT_FOUND, None),
        ("user4", "old_pass", "new_pass", None, "token", True, None, CODE_BAD_REQUEST, None),
        # Token error
        ("user5", "old_pass", "new_pass", b"salt5", 'token', True, JWTError("err", CODE_UNAUTHORIZED), CODE_UNAUTHORIZED, "err"),
    ]
)
def test_change_password_cases(
    username, old_password, new_password, salt, token, user_exists, token_error, expected_status, expected_error,
    mock_db, app_ctx, mocker
):
    from server.utils.auth import change_password
    # Patch DB session
    if user_exists:
        user = Users(id=1, username=username, password=hash_password(old_password), salt=b"oldsalt")
        mock_db.query().filter_by().first.return_value = user
    else:
        mock_db.query().filter_by().first.return_value = None
    mocker.patch('server.utils.auth.get_session', return_value=mock_session_ctx(mock_db))
    # Patch get_user_id_from_token
    if token_error:
        mocker.patch('server.utils.auth.get_user_id_from_token', side_effect=token_error)
    else:
        mocker.patch('server.utils.auth.get_user_id_from_token', return_value=1)
    # Call function
    response = change_password(token, new_password, salt)
    assert response[1] == expected_status
    data = response[0].get_json()
    if expected_error:
        assert data["error"] == expected_error
    elif expected_status == CODE_SUCCESS:
        # Check if salt was updated
        assert user.salt == salt
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

@pytest.mark.parametrize("token, new_username, user_exists, token_error, username_conflict, same_username, expected_status, expected_error", [
    (None, "new", True, None, False, False, CODE_BAD_REQUEST, None),
    ("token", None, True, None, False, False, CODE_BAD_REQUEST, None),
    ("token", "new", True, JWTError("err", CODE_UNAUTHORIZED), False, False, CODE_UNAUTHORIZED, "err"),
    ("token", "new", False, None, False, False, CODE_NOT_FOUND, None),
    ("token", "new", True, None, True, False, CODE_CONFLICT, None),
    ("token", "same", True, None, False, True, CODE_BAD_REQUEST, None),
    ("token", "unique", True, None, False, False, CODE_SUCCESS, None)
])
def test_change_username_cases(token, new_username, user_exists, token_error, username_conflict, same_username, expected_status, expected_error, mock_db, app_ctx, mocker):
    user = Users(id=1, username="same") if user_exists else None
    mock_db.query().filter_by().first.side_effect = [user, Users(username=new_username) if username_conflict else None]
    if token_error:
        mocker.patch('server.utils.auth.get_user_id_from_token', side_effect=token_error)
    else:
        mocker.patch('server.utils.auth.get_user_id_from_token', return_value=1)
    mocker.patch('server.utils.auth.get_session', return_value=mock_session_ctx(mock_db))
    response = change_username(token, new_username)
    assert response[1] == expected_status
    data = response[0].get_json()
    if expected_error:
        assert data["error"] == expected_error
    elif expected_status == CODE_SUCCESS:
        assert "message" in data
    else:
        assert "error" in data

@pytest.mark.parametrize(
    "token_error, user_exists, expected_status, expected_error, expected_username, expected_public_key",
    [
        # Invalid token
        (JWTError("Missing required fields", CODE_BAD_REQUEST), True, CODE_BAD_REQUEST, "Missing required fields", None, None),
        # Invalid user (user not found)
        (None, False, CODE_NOT_FOUND, "User not found", None, None),
        # Success
        (None, True, CODE_SUCCESS, None, "user", "pk"),
    ]
)
def test_get_current_user_cases(token_error, user_exists, expected_status, expected_error, expected_username, expected_public_key, mock_db, app_ctx, mocker):
    from server.utils.auth import get_current_user

    # Patch get_current_token
    if token_error:
        mocker.patch('server.utils.auth.get_current_token', side_effect=token_error)
    else:
        mocker.patch('server.utils.auth.get_current_token', return_value="token")
    mocker.patch('server.utils.auth.get_user_id_from_token', return_value=1)
    # Always patch get_session to avoid real DB connection
    mocker.patch('server.utils.auth.get_session', return_value=mock_session_ctx(mock_db))
    if token_error:
        mocker.patch('server.utils.auth.get_user_id_from_token', side_effect=Exception("Should not be called when token_error is set"))
        mock_db.query().filter_by().first.return_value = None
    elif user_exists is None:
        mock_db.query().filter_by().first.return_value = None
    elif user_exists:
        user = Users(
            id=1, 
            username="user", 
            password="pw", 
            public_key="pk", 
            spk="c3BrX2tleQ==",  # Add base64 encoded spk
            spk_signature="c2lnbmF0dXJl",  # Add base64 encoded spk_signature
            salt=b"salt", 
            created_at="now", 
            updated_at="now"
        )
        mock_db.query().filter_by().first.return_value = user
    else:
        mock_db.query().filter_by().first.return_value = None
    resp, status = get_current_user()
    assert status == expected_status
    if expected_error:
        if hasattr(resp, 'get_json'):
            assert resp.get_json()["error"] == expected_error
        else:
            assert resp.get("error") == expected_error
    elif expected_status == CODE_SUCCESS:
        assert resp["username"] == expected_username
        assert resp["public_key"] == expected_public_key
    else:
        assert "error" in resp

@pytest.mark.parametrize(
    "username, expected_status, expected_public_key",
    [
        ("valid_user", CODE_SUCCESS, "cHViX2tleQ=="),  # Success
        ("nonexistent_user", CODE_NOT_FOUND, None),  # User not found
        (None, CODE_BAD_REQUEST, None),  # Missing username
    ]
)
def test_get_public_key_cases(username, expected_status, expected_public_key, mock_db, app_ctx, mocker):
    from server.utils.auth import get_public_key

    if username:
        user = Users(username=username, public_key="cHViX2tleQ==") if expected_status == CODE_SUCCESS else None
        mock_db.query().filter_by().first.return_value = user
    else:
        mock_db.query().filter_by().first.return_value = None

    mocker.patch('server.utils.auth.get_session', return_value=mock_session_ctx(mock_db))
    response = get_public_key(username)
    assert response[1] == expected_status
    data = response[0].get_json()
    if expected_status == CODE_SUCCESS:
        assert data["public_key"] == expected_public_key
    else:
        assert "error" in data

@pytest.mark.parametrize("user_info, mock_count, expected_result", [
    ({"user_id": 1, "username": "user1"}, 5, 5),  # User has unused OTPKs
    ({"user_id": 2, "username": "user2"}, 0, 0),  # User has no unused OTPKs
    ({"user_id": 3, "username": "user3"}, 1, 1),  # User has exactly 1 unused OTPK
    ({"user_id": 4}, 10, 10),  # Missing username but has user_id
])
def test_get_count_otpk_cases(user_info, mock_count, expected_result, mock_db, app_ctx, mocker):
    from server.utils.auth import get_count_otpk
    
    mock_db.query().filter_by().count.return_value = mock_count
    mocker.patch('server.utils.auth.get_session', return_value=mock_session_ctx(mock_db))
    
    result = get_count_otpk(user_info)
    assert result == expected_result

@pytest.mark.parametrize(
    "user_info, spk, spk_signature, user_exists, expected_status",
    [
        # Success case
        ({"user_id": 1, "username": "user1"}, "c3BrX2tleQ==", "c2lnbmF0dXJl", True, CODE_SUCCESS),
        # User not found
        ({"user_id": 1, "username": "user1"}, "c3BrX2tleQ==", "c2lnbmF0dXJl", False, CODE_NOT_FOUND),
        # Invalid base64 format
        ({"user_id": 1, "username": "user1"}, "invalid_base64!", "c2lnbmF0dXJl", True, CODE_BAD_REQUEST),
        # Missing user_info
        (None, "c3BrX2tleQ==", "c2lnbmF0dXJl", True, CODE_BAD_REQUEST),
        # Missing spk
        ({"user_id": 1, "username": "user1"}, None, "c2lnbmF0dXJl", True, CODE_BAD_REQUEST),
        # Missing spk_signature
        ({"user_id": 1, "username": "user1"}, "c3BrX2tleQ==", None, True, CODE_BAD_REQUEST),
        # Invalid spk_signature format
        ({"user_id": 1, "username": "user1"}, "c3BrX2tleQ==", "invalid_base64!", True, CODE_BAD_REQUEST),
    ]
)
def test_update_spk_cases(user_info, spk, spk_signature, user_exists, expected_status, mock_db, app_ctx, mocker):
    # Set up mock database responses
    if user_exists:
        user = Users(id=1, username="user1")
        mock_db.query().filter_by().first.return_value = user
    else:
        mock_db.query().filter_by().first.return_value = None
    
    # Patch the database session
    mocker.patch('server.utils.auth.get_session', return_value=mock_session_ctx(mock_db))
    
    # Call the function
    response = update_spk(user_info, spk, spk_signature)
    
    # Verify response status
    assert response[1] == expected_status
    
    # Verify response content
    if expected_status == CODE_SUCCESS:
        # Verify that the SPK and signature were updated
        assert user.spk == spk
        assert user.spk_signature == spk_signature
        assert user.updated_at is not None
        # Verify that the database was committed
        assert mock_db.commit.call_count == 1
    else:
        assert "error" in response[0]
        # Verify that no database changes were made for error cases
        assert mock_db.commit.call_count == 0

@pytest.mark.parametrize(
    "otpks, user_info, expected_status",
    [
        (["otk1", "otk2"], {"user_id": 1, "username": "user1"}, CODE_CREATED), # Success case
        ([], {"user_id": 1, "username": "user1"}, CODE_BAD_REQUEST),  # Empty OTPKs list
        (["otk1"], None, CODE_BAD_REQUEST), #Missing user_info
        (["otk1"], {"username": "user1"}, CODE_BAD_REQUEST),# Missing user_id in user_info
        (["otk1"], {"user_id": 1, "username": "user1"}, CODE_CREATED),# Single OTPK
        (["invalid_base64!"], {"user_id": 1, "username": "user1"}, CODE_BAD_REQUEST), # Invalid base64
        (None, {"user_id": 1, "username": "user1"}, CODE_BAD_REQUEST), # Missing OTPKs
    ]
)
def test_add_otpk_cases(otpks, user_info, expected_status, mock_db, app_ctx, mocker):
    from server.utils.auth import add_otpks
    
    # Patch the database session
    mocker.patch('server.utils.auth.get_session', return_value=mock_session_ctx(mock_db))
    
    # Call the function
    response = add_otpks(otpks, user_info)
    
    # Verify response status
    assert response[1] == expected_status
    
    # Verify database interactions for success cases
    if expected_status == CODE_CREATED:
        assert mock_db.add.call_count == len(otpks)
        assert mock_db.commit.call_count == 1
        
        # Verify OTPK object creation
        for call_args in mock_db.add.call_args_list:
            otk_obj = call_args[0][0]
            assert isinstance(otk_obj, OTPK)
            assert otk_obj.user_id == user_info["user_id"]
            assert otk_obj.key in otpks
            assert otk_obj.used == 0
            assert otk_obj.created_at is not None
            assert otk_obj.updated_at is not None
            # Verify that created_at and updated_at are set to the same value initially
            assert otk_obj.created_at == otk_obj.updated_at
    else:
        assert "error" in response[0]
        assert mock_db.commit.call_count == 0

@pytest.mark.parametrize(
    "username, user_exists, has_unused_otpk, expected_status, expected_otpk",
    [
        ("valid_user", True, True, CODE_SUCCESS, "test_otpk"),  # Success case
        ("nonexistent_user", False, False, CODE_NOT_FOUND, None),  # User not found
        ("user_no_otpk", True, False, CODE_NOT_FOUND, None),  # User exists but no unused OTPK
        (None, False, False, CODE_BAD_REQUEST, None),  # Missing username
        ("valid_user", True, True, CODE_SUCCESS, "test_otpk"),  # Success case with updated_at
    ]
)
def test_retrieve_key_bundle_cases(username, user_exists, has_unused_otpk, expected_status, expected_otpk, mock_db, app_ctx, mocker):
    from server.utils.auth import retrieve_key_bundle
    
    # Set up mock database responses
    if user_exists:
        current_time = datetime.now(timezone.utc)
        user = Users(
            id=1, 
            username=username,
            spk="test_spk",
            spk_signature="test_signature",
            spk_updated_at=current_time
        )
        otpk = OTPK(key=expected_otpk, used=0) if has_unused_otpk else None
        mock_db.query().filter_by().first.side_effect = [user, otpk]
    else:
        mock_db.query().filter_by().first.return_value = None
    
    # Patch the database session
    mocker.patch('server.utils.auth.get_session', return_value=mock_session_ctx(mock_db))
    
    # Call the function
    response = retrieve_key_bundle(username)
    
    # Verify response status
    assert response[1] == expected_status
    
    # Verify response content
    if expected_status == CODE_SUCCESS:
        assert response[0]["otpk"] == expected_otpk
        assert response[0]["spk"] == "test_spk"
        assert response[0]["spk_signature"] == "test_signature"
        assert "updatedAt" in response[0]
        # Verify that the OTPK was marked as used
        assert otpk.used == 1
        assert otpk.updated_at is not None
        # Verify that the database was committed
        assert mock_db.commit.call_count == 1
    else:
        assert "error" in response[0]
        # Verify that no database changes were made for error cases
        assert mock_db.commit.call_count == 0