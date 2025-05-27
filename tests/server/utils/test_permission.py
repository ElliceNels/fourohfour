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

@pytest.mark.parametrize("user_exists, public_key, expected_status", [
    (True, "testkey", CODE_OK),
    (False, None, CODE_NOT_FOUND),
])
def test_get_user_public_key(user_exists, public_key, expected_status):
    mock_user = MagicMock()
    mock_user.public_key = public_key
    with patch("server.utils.permission.get_session") as mock_get_session, \
         patch("server.utils.permission.Users") as mock_users:
        mock_db = MagicMock()
        mock_get_session.return_value.__enter__.return_value = mock_db
        if user_exists:
            mock_db.query.return_value.get.return_value = mock_user
        else:
            mock_db.query.return_value.get.return_value = None
        resp, status = permission.get_user_public_key(1)
        data = resp.get_json()
        if user_exists:
            assert data["public_key"] == public_key
            assert status == CODE_OK
        else:
            assert data["error"] == "User not found"
            assert status == CODE_NOT_FOUND

@pytest.mark.parametrize("file_exists, owner_matches, recipient_exists, permission_exists, raises, expected_status", [
    (True, True, True, False, False, CODE_CREATED),   # Success
    (False, True, True, False, False, CODE_NOT_FOUND),  # File not found
    (True, False, True, False, False, CODE_FORBIDDEN),  # Not owner
    (True, True, False, False, False, CODE_NOT_FOUND),  # Recipient not found
    (True, True, True, True, False, CODE_CONFLICT),    # Permission exists
    (True, True, True, False, True, CODE_ERROR),    # Exception
])
def test_create_file_permission(file_exists, owner_matches, recipient_exists, permission_exists, raises, expected_status):
    with patch("server.utils.permission.get_session") as mock_get_session, \
         patch("server.utils.permission.Files") as mock_files, \
         patch("server.utils.permission.Users") as mock_users, \
         patch("server.utils.permission.FilePermissions") as mock_perms:
        mock_db = MagicMock()
        mock_get_session.return_value.__enter__.return_value = mock_db
        mock_file = MagicMock()
        mock_file.owner_id = 1 if owner_matches else 2
        mock_recipient = MagicMock()
        mock_perm = MagicMock()
        # File
        mock_db.query.return_value.get.side_effect = lambda x: (
            mock_file if file_exists and x == 1 else (mock_recipient if recipient_exists and x == 2 else None)
        )
        # Recipient
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
        mock_db.query.side_effect = query_side_effect
        # Exception
        if raises:
            mock_db.commit.side_effect = Exception("fail")
        else:
            mock_db.commit.side_effect = None
        resp, status = permission.create_file_permission(1, 2, "key", 1)
        data = resp.get_json()
        if expected_status == CODE_CREATED:
            assert data["message"] == "Permission created successfully"
            assert status == CODE_CREATED
        elif expected_status == CODE_NOT_FOUND:
            assert data["error"] in ["File not found", "Recipient user not found"]
            assert status == CODE_NOT_FOUND
        elif expected_status == CODE_FORBIDDEN:
            assert data["error"] == "Not authorized to share this file"
            assert status == CODE_FORBIDDEN
        elif expected_status == CODE_CONFLICT:
            assert data["error"] == "Permission already exists"
            assert status == CODE_CONFLICT
        elif expected_status == CODE_ERROR:
            assert data["error"] == "fail"
            assert status == CODE_ERROR

@pytest.mark.parametrize("file_exists, owner_matches, permission_exists, raises, expected_status", [
    (True, True, True, False, CODE_OK),   # Success
    (False, True, True, False, CODE_NOT_FOUND),  # File not found
    (True, False, True, False, CODE_FORBIDDEN),  # Not owner
    (True, True, False, False, CODE_NOT_FOUND),  # Permission not found
    (True, True, True, True, CODE_ERROR),    # Exception
])
def test_remove_file_permission(file_exists, owner_matches, permission_exists, raises, expected_status):
    with patch("server.utils.permission.get_session") as mock_get_session, \
         patch("server.utils.permission.Files") as mock_files, \
         patch("server.utils.permission.FilePermissions") as mock_perms:
        mock_db = MagicMock()
        mock_get_session.return_value.__enter__.return_value = mock_db
        mock_file = MagicMock()
        mock_file.owner_id = 1 if owner_matches else 2
        mock_perm = MagicMock()
        # File
        mock_db.query.return_value.get.side_effect = lambda x: mock_file if file_exists else None
        # Permission
        def query_side_effect(*args, **kwargs):
            class Query:
                def get(self, x):
                    return mock_file if file_exists else None
                def filter_by(self, **kwargs):
                    class F:
                        def first(self):
                            return mock_perm if permission_exists else None
                    return F()
            return Query()
        mock_db.query.side_effect = query_side_effect
        # Exception
        if raises:
            mock_db.commit.side_effect = Exception("fail")
        else:
            mock_db.commit.side_effect = None
        resp, status = permission.remove_file_permission(1, 2, 1)
        data = resp.get_json()
        if expected_status == CODE_OK:
            assert data["message"] == "Permission removed successfully"
            assert status == CODE_OK
        elif expected_status == CODE_NOT_FOUND:
            assert data["error"] in ["File not found", "Permission not found"]
            assert status == CODE_NOT_FOUND
        elif expected_status == CODE_FORBIDDEN:
            assert data["error"] == "Not authorized to modify permissions for this file"
            assert status == CODE_FORBIDDEN
        elif expected_status == CODE_ERROR:
            assert data["error"] == "fail"
            assert status == CODE_ERROR
