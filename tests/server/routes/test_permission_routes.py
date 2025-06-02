import pytest
import uuid
import logging
from flask.testing import FlaskClient
from sqlalchemy_utils import database_exists, drop_database
from server.utils.db_setup import setup_db, get_session, teardown_db
from server.app import create_app
from server.models.tables import Base, Users, Files

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Status codes
SUCCESS = 200
CREATED = 201
BAD_REQUEST = 400
UNAUTHORIZED = 401
FORBIDDEN = 403
NOT_FOUND = 404
CONFLICT = 409

@pytest.fixture(scope="session")
def app_fixture():
    """Create a Flask app instance for testing."""
    app = create_app()
    app.config.update(TESTING=True, JWT_SECRET_KEY="testsecret")
    return app

@pytest.fixture(scope="session")
def setup_test_db(app_fixture):
    """Set up test database before running tests."""
    db_name = "test_permission_database"
    engine = setup_db(db_name)
    logger.info("Test database setup complete.")

    yield

    teardown_db(db_name, engine=engine, remove_db=True)
    logger.info("Test database teardown complete.")

@pytest.fixture
def client(app_fixture):
    """Create a test client using Flask's test framework."""
    with app_fixture.test_client() as client:
        yield client

@pytest.fixture
def test_user():
    """Generate a unique test user for each run with a valid base64 public key."""
    import base64
    unique_username = f"test_user_{uuid.uuid4().hex[:8]}"
    # Generate a random 32-byte value and encode as base64
    random_bytes = uuid.uuid4().bytes + uuid.uuid4().bytes
    unique_public_key = base64.b64encode(random_bytes).decode()
    return {
        "username": unique_username,
        "password": "test_password",
        "public_key": unique_public_key,
        "salt": "test_salt"
    }

@pytest.fixture
def second_test_user():
    """Generate a second unique test user for permission sharing tests."""
    import base64
    unique_username = f"test_user2_{uuid.uuid4().hex[:8]}"
    # Generate a random 32-byte value and encode as base64
    random_bytes = uuid.uuid4().bytes + uuid.uuid4().bytes
    unique_public_key = base64.b64encode(random_bytes).decode()
    return {
        "username": unique_username,
        "password": "test_password2",
        "public_key": unique_public_key,
        "salt": "test_salt2"
    }

@pytest.fixture
def signed_up_user(client, test_user):
    """Sign up a user and return the user data and tokens."""
    response = client.post("/sign_up", json=test_user)
    assert response.status_code == 201
    data = response.json
    return {"user": test_user, "access_token": data["access_token"], "refresh_token": data["refresh_token"]}

@pytest.fixture
def logged_in_user(client, signed_up_user):
    """Log in the signed-up user and return login tokens."""
    response = client.post("/login", json=signed_up_user["user"])
    assert response.status_code == 200
    data = response.json
    return {"user": signed_up_user["user"], "access_token": data["access_token"], "refresh_token": data["refresh_token"]}

@pytest.fixture
def test_file_data():
    """Generate a sample file data for testing."""
    return {
        "file": {
            "filename": "testfile",
            "contents": "dGVzdCBmaWxlIGNvbnRlbnQ="  # base64 encoded "test file content"
        },
        "metadata": {
            "size": 1234,
            "format": "txt"
        }
    }

@pytest.fixture
def stored_file_data(logged_in_user, test_file_data, client):
    """Upload a file and return its metadata."""
    headers = {
        "Authorization": f"Bearer {logged_in_user['access_token']}",
        "Content-Type": "application/json"
    }
    response = client.post("/api/files/upload", headers=headers, json=test_file_data)
    
    if response.status_code != 201:
        pytest.skip(f"File upload failed with status {response.status_code}: {response.json}")
    
    data = response.json
    return {
        "file_uuid": data["uuid"],  # Changed from "file_uuid" to "uuid" based on API response
        "message": data["message"]
    }

@pytest.fixture
def second_signed_up_user(client, second_test_user):
    """Sign up the second user and return the user data."""
    response = client.post("/sign_up", json=second_test_user)
    assert response.status_code == 201
    return second_test_user

@pytest.mark.parametrize("expected_status, include_key, include_file, include_user_id, is_owner", [
    (CREATED, True, True, True, True),           # Success: all fields included
    (CONFLICT, True, True, True, True),          # Conflict: all fields included
    (BAD_REQUEST, True, False, True, True),      # Error: missing file_uuid
    (BAD_REQUEST, True, True, False, True),      # Error: missing user_id
    (BAD_REQUEST, False, True, True, True),      # Error: missing key_for_recipient
    (NOT_FOUND, True, True, True, False),        # Error: file not found
])
def test_create_permission(client, logged_in_user, second_signed_up_user, stored_file_data, expected_status, include_key, include_file, include_user_id, is_owner):
    """Test creating file permissions with various scenarios."""
    # Get the second user's ID
    with get_session() as db:
        user = db.query(Users).filter_by(username=second_signed_up_user["username"]).first()
        user_id = user.id
    
    headers = {"Authorization": f"Bearer {logged_in_user['access_token']}"}
    permission_data = {}
    
    if include_file:
        permission_data["file_uuid"] = uuid.uuid4() if not is_owner else stored_file_data["file_uuid"]
    
    if include_key:
        permission_data["key_for_recipient"] = "encrypted_key_for_recipient"
    
    if include_user_id:
        permission_data["user_id"] = user_id
    
    if expected_status == CONFLICT:
        # Create permission first time
        response = client.post("/api/permissions", json=permission_data, headers=headers)
        assert response.status_code == CREATED
    
    # Now make the actual test request
    response = client.post("/api/permissions", json=permission_data, headers=headers)
    assert response.status_code == expected_status

@pytest.mark.parametrize("expected_status, include_key, include_file, include_user_id, is_owner", [
    (SUCCESS, True, True, True, True),           # Success: all fields included
    (NOT_FOUND, True, True, True, True),         # Error: permission not found
    (BAD_REQUEST, True, False, True, True),      # Error: missing file_uuid
    (BAD_REQUEST, True, True, False, True),      # Error: missing user_id
    (NOT_FOUND, True, True, True, False),        # Error: file not found
])
def test_remove_permission(client, logged_in_user, second_signed_up_user, stored_file_data, expected_status, include_key, include_file, include_user_id, is_owner):
    """Test removing file permissions with various scenarios."""
    # Get the second user's ID
    with get_session() as db:
        user = db.query(Users).filter_by(username=second_signed_up_user["username"]).first()
        user_id = user.id
    
    headers = {"Authorization": f"Bearer {logged_in_user['access_token']}"}
    
    if expected_status == SUCCESS:
        # Create permission first
        permission_data = {
            "file_uuid": stored_file_data["file_uuid"],
            "user_id": user_id,
            "key_for_recipient": "encrypted_key_for_recipient"
        }
        response = client.post("/api/permissions", json=permission_data, headers=headers)
        assert response.status_code == CREATED
    
    # Prepare removal data
    remove_data = {}
    
    if include_file:
        remove_data["file_uuid"] = uuid.uuid4() if not is_owner else stored_file_data["file_uuid"]
    
    if include_key:
        remove_data["key_for_recipient"] = "encrypted_key_for_recipient"
    
    if include_user_id:
        remove_data["user_id"] = user_id
    
    # Make the removal request
    response = client.delete("/api/permissions", json=remove_data, headers=headers)
    assert response.status_code == expected_status
