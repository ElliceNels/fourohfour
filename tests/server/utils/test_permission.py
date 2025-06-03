import pytest
from unittest.mock import patch, MagicMock
from server.utils import permission
from flask import Flask
import uuid
import base64

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
                        # If querying Files table
                        if args[0].__name__ == 'Files':
                            return mock_file if file_exists else None
                        # If querying FilePermissions table
                        elif args[0].__name__ == 'FilePermissions':
                            return mock_perm if permission_exists else None
                        return None
                return F()
        return Query()
    return query_side_effect


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
    with patch("server.utils.permission.get_session") as mock_get_session:
        mock_db = MagicMock()
        # Mock the context manager returned by get_session
        mock_get_session.return_value.__enter__.return_value = mock_db
        mock_file = MagicMock()
        # Give the file an owner_id based on whether this test is simulating an owner match
        mock_file.owner_id = 1 if owner_matches else 2
        mock_file.id = 123  # Add an internal ID for the file
        mock_recipient = MagicMock()
        mock_recipient.username = "test_user"
        mock_perm = MagicMock()
        
        # Mock the database query to return a file or recipient depending on input        
        def query_side_effect(*args, **kwargs):
            if args[0].__name__ == 'Files':
                file_query = MagicMock()
                if file_exists:
                    file_query.filter_by().first.return_value = mock_file
                else:
                    file_query.filter_by().first.return_value = None
                return file_query
            elif args[0].__name__ == 'Users':
                user_query = MagicMock()
                if recipient_exists:
                    user_query.filter_by().first.return_value = mock_recipient
                else:
                    user_query.filter_by().first.return_value = None
                return user_query
            elif args[0].__name__ == 'FilePermissions':
                perm_query = MagicMock()
                if permission_exists:
                    perm_query.filter_by().first.return_value = mock_perm
                else:
                    perm_query.filter_by().first.return_value = None
                return perm_query
            return MagicMock()
        
        mock_db.query.side_effect = query_side_effect
        
        # Simulate an exception on commit if raises is True
        if raises:
            mock_db.commit.side_effect = Exception("fail")
        else:
            mock_db.commit.side_effect = None

        # Generate test keys
        key_bytes = uuid.uuid4().bytes + uuid.uuid4().bytes
        otpk_bytes = uuid.uuid4().bytes + uuid.uuid4().bytes
        ephemeral_key_bytes = uuid.uuid4().bytes + uuid.uuid4().bytes
        
        key_for_recipient = base64.b64encode(key_bytes).decode()
        otpk = base64.b64encode(otpk_bytes).decode()
        ephemeral_key = base64.b64encode(ephemeral_key_bytes).decode()

        # Call the function with a UUID
        resp, status = permission.create_file_permission(
            file_uuid="test-uuid",
            username="test_user",
            key_for_recipient=key_for_recipient,
            otpk=otpk,
            ephemeral_key=ephemeral_key,
            owner_id=1
        )
        data = resp.get_json()
        assert status == expected_status

        # For success, check for 'message'; for errors, check for 'error'
        if status in (CODE_CREATED, CODE_OK):
            assert "message" in data
        else:
            assert "error" in data

@pytest.mark.parametrize("file_exists, owner_matches, permission_exists, raises, expected_status", [
    (True, True, True, False, CODE_OK),           # Success
    (False, True, True, False, CODE_NOT_FOUND),   # File not found
    (True, False, True, False, CODE_FORBIDDEN),   # Not owner
    (True, True, False, False, CODE_NOT_FOUND),   # Permission not found
    (True, True, True, True, CODE_ERROR),         # Exception
])
def test_remove_file_permission(file_exists, owner_matches, permission_exists, raises, expected_status):
    with patch("server.utils.permission.get_session") as mock_get_session:
        mock_db = MagicMock()
        mock_get_session.return_value.__enter__.return_value = mock_db
        mock_file = MagicMock()
        mock_file.owner_id = 1 if owner_matches else 2
        mock_file.id = 123  # Add an internal ID for the file
        mock_user = MagicMock()
        mock_user.username = "test_user"
        mock_perm = MagicMock()
        
        # Mock the database queries
        def query_side_effect(*args, **kwargs):
            if args[0].__name__ == 'Files':
                file_query = MagicMock()
                if file_exists:
                    file_query.filter_by().first.return_value = mock_file
                else:
                    file_query.filter_by().first.return_value = None
                return file_query
            elif args[0].__name__ == 'Users':
                user_query = MagicMock()
                user_query.filter_by().first.return_value = mock_user
                return user_query
            elif args[0].__name__ == 'FilePermissions':
                perm_query = MagicMock()
                if permission_exists:
                    perm_query.filter_by().first.return_value = mock_perm
                else:
                    perm_query.filter_by().first.return_value = None
                return perm_query
            return MagicMock()
        
        mock_db.query.side_effect = query_side_effect
        
        # Simulate an exception on commit if raises is True
        if raises:
            mock_db.commit.side_effect = Exception("fail")
        else:
            mock_db.commit.side_effect = None

        # Call the function with a UUID
        resp, status = permission.remove_file_permission(
            file_uuid="test-uuid",
            username="test_user",
            owner_id=1
        )
        data = resp.get_json()
        assert status == expected_status

        # For success, check for 'message'; for errors, check for 'error'
        if status in (CODE_CREATED, CODE_OK):
            assert "message" in data
        else:
            assert "error" in data

@pytest.mark.parametrize("file_exists, owner_matches, raises, expected_status", [
    (True, True, False, CODE_OK),           # Success
    (False, True, False, CODE_NOT_FOUND),   # File not found
    (True, False, False, CODE_FORBIDDEN),   # Not owner
    (True, True, True, CODE_ERROR),         # Exception
])
def test_get_file_permissions(file_exists, owner_matches, raises, expected_status):
    with patch("server.utils.permission.get_session") as mock_get_session:
        mock_db = MagicMock()
        mock_get_session.return_value.__enter__.return_value = mock_db
        mock_file = MagicMock()
        mock_file.owner_id = 1 if owner_matches else 2
        mock_file.id = 123
        mock_user = MagicMock()
        mock_user.username = "testuser"
        mock_user.id = 2
        mock_perm = MagicMock()
        mock_perm.user_id = 2
        
        # Mock the database queries
        def query_side_effect(*args, **kwargs):
            if args[0].__name__ == 'Files':
                file_query = MagicMock()
                if file_exists:
                    file_query.filter_by().first.return_value = mock_file
                else:
                    file_query.filter_by().first.return_value = None
                return file_query
            elif args[0].__name__ == 'FilePermissions':
                perm_query = MagicMock()
                if file_exists and owner_matches:
                    perm_query.filter_by().all.return_value = [mock_perm]
                else:
                    perm_query.filter_by().all.return_value = []
                return perm_query
            elif args[0].__name__ == 'Users':
                user_query = MagicMock()
                user_query.filter_by().first.return_value = mock_user
                return user_query
            return MagicMock()
        
        mock_db.query.side_effect = query_side_effect
        
        # Simulate an exception if raises is True
        if raises:
            mock_db.query.side_effect = Exception("fail")

        # Call the function with a UUID
        resp, status = permission.get_file_permissions("test-uuid", 1)
        data = resp.get_json()
        assert status == expected_status

        # For success, check for 'permissions'; for errors, check for 'error'
        if status == CODE_OK:
            assert "permissions" in data
            assert len(data["permissions"]) == 1
            assert data["permissions"][0]["username"] == "testuser"
        else:
            assert "error" in data
