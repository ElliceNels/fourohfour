import pytest
from unittest.mock import patch, MagicMock
from server.utils import permission
from flask import Flask

CODE_OK = 200
CODE_CREATED = 201
CODE_NOT_FOUND = 404
CODE_FORBIDDEN = 403
CODE_CONFLICT = 409
CODE_ERROR = 500

@pytest.fixture(scope="module")
def app_fixture():
    app = Flask(__name__)
    app.config.update(TESTING=True, JWT_SECRET_KEY="testsecret")
    return app

@pytest.fixture(autouse=True)
def app_ctx(app_fixture):
    with app_fixture.app_context():
        yield

# Mock the query method to simulate permission existence
# Equivalent to: `db.query(FilePermissions).filter_by(file_id=file_id, user_id=user_id).first()`
def make_query_side_effect(mock_file, file_exists, mock_recipient, recipient_exists, mock_perm, permission_exists):
    def query_side_effect(*args, **kwargs):
        class Query:
            def get(self, x):
                if x == 1:
                    return mock_file if file_exists else None
                if x == 2:
                    return mock_recipient if recipient_exists else None
            def filter_by(self, **kwargs):
                class F:
                    def first(self):
                        return mock_perm if permission_exists else None
                return F()
        return Query()
    return query_side_effect

@pytest.mark.parametrize("user_exists, public_key, expected_status", [
    (True, "testkey", CODE_OK), # Success case
    (False, None, CODE_NOT_FOUND), # User does not exist (key doesn't matter)
])
def test_get_user_public_key(user_exists, public_key, expected_status):
    # Mock the user object
    mock_user = MagicMock()
    # Set the public_key attribute if the user exists
    mock_user.public_key = public_key
    # Patch the get_session function from the permission module
    with patch("server.utils.permission.get_session") as mock_get_session:
        mock_db = MagicMock()
        # Mock the context manager returned by get_session
        mock_get_session.return_value.__enter__.return_value = mock_db
        # Mock the database query to return a user or None (if user does not exist)
        if user_exists:
            # This mirrors the db query behavior in the actual code
            mock_db.query.return_value.get.return_value = mock_user
        else:
            mock_db.query.return_value.get.return_value = None

        # NOW: Call the function to test
        resp, status = permission.get_user_public_key(1)
        data = resp.get_json()
        if user_exists:
            assert data["public_key"] == public_key
            assert status == expected_status
        else:
            assert data["error"] == "User not found"
            assert status == expected_status

@pytest.mark.parametrize("file_exists, owner_matches, recipient_exists, permission_exists, raises, expected_status", [
    (True, True, True, False, False, CODE_CREATED),   # Success
    (False, True, True, False, False, CODE_NOT_FOUND),  # File not found
    (True, False, True, False, False, CODE_FORBIDDEN),  # Not owner
    (True, True, False, False, False, CODE_NOT_FOUND),  # Recipient not found
    (True, True, True, True, False, CODE_CONFLICT),    # Permission exists
    (True, True, True, False, True, CODE_ERROR),    # Exception
])
def test_create_file_permission(file_exists, owner_matches, recipient_exists, permission_exists, raises, expected_status):
    # Patch the get_session, Files, Users, and FilePermissions objects in the permission module
    # Essentially, we are setting up the return of the db interactions based on the parameters
    with patch("server.utils.permission.get_session") as mock_get_session:
        mock_db = MagicMock()
        # Mock the context manager returned by get_session
        mock_get_session.return_value.__enter__.return_value = mock_db
        mock_file = MagicMock()
        # Give the file an owner_id based on whether this test is simulating an owner match
        mock_file.owner_id = 1 if owner_matches else 2
        mock_recipient = MagicMock()
        mock_perm = MagicMock()
        # Mock the database query to return a file or recipient depending on input        
        mock_db.query.side_effect = make_query_side_effect(
            mock_file, file_exists, mock_recipient, recipient_exists, mock_perm, permission_exists
        )
        # Simulate an exception on commit if raises is True
        if raises:
            mock_db.commit.side_effect = Exception("fail")
        else:
            mock_db.commit.side_effect = None

        # NOW: Actually call the function to test
        resp, status = permission.create_file_permission(1, 2, "key", 1)
        data = resp.get_json()
        assert status == expected_status

        # For success, check for 'message'; for errors, check for 'error'
        if status in (CODE_CREATED, CODE_OK):
            assert "message" in data
        else:
            assert "error" in data

@pytest.mark.parametrize("file_exists, owner_matches, permission_exists, raises, expected_status", [
    (True, True, True, False, CODE_OK),   # Success
    (False, True, True, False, CODE_NOT_FOUND),  # File not found
    (True, False, True, False, CODE_FORBIDDEN),  # Not owner
    (True, True, False, False, CODE_NOT_FOUND),  # Permission not found
    (True, True, True, True, CODE_ERROR),    # Exception
])
def test_remove_file_permission(file_exists, owner_matches, permission_exists, raises, expected_status):
    # Patch the get_session, Files, and FilePermissions objects in the permission module
    with patch("server.utils.permission.get_session") as mock_get_session:
        mock_db = MagicMock()
        # Mock the context manager returned by get_session
        mock_get_session.return_value.__enter__.return_value = mock_db
        # File and permission mock objects
        mock_file = MagicMock()
        mock_file.owner_id = 1 if owner_matches else 2
        mock_perm = MagicMock()
        # Use the shared query side effect
        mock_db.query.side_effect = make_query_side_effect(
            mock_file, file_exists, None, False, mock_perm, permission_exists
        )
        # Simulate an exception on commit if raises is True
        if raises:
            #  This simulates a database error during commit
            mock_db.commit.side_effect = Exception("fail")
        else:
            mock_db.commit.side_effect = None

        # NOW: Actually call the function to test
        resp, status = permission.remove_file_permission(1, 2, 1)
        data = resp.get_json()

        assert status == expected_status
        # For success, check for 'message'; for errors, check for 'error'
        if status in (CODE_CREATED, CODE_OK):
            assert "message" in data
        else:
            assert "error" in data
