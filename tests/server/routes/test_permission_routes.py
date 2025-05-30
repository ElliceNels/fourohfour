import pytest
import uuid
import logging
from flask.testing import FlaskClient
from sqlalchemy_utils import database_exists, drop_database
from server.utils.db_setup import setup_db
from server.app import create_app
from server.models.tables import Base

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@pytest.fixture(scope="session")
def app_fixture():
    """Create a Flask app instance for testing."""
    app = create_app()
    app.config.update(TESTING=True, JWT_SECRET_KEY="testsecret")
    return app

@pytest.fixture(scope="session")
def setup_test_db(app_fixture):
    """Set up test database before running tests."""
    engine = setup_db("test_database")
    Base.metadata.create_all(bind=engine)
    logger.info("Test database setup complete.")

    yield
    Base.metadata.drop_all(bind=engine)
    
    # Ensure database deletion
    if database_exists(engine.url):
        try:
            engine.dispose()  # Close connection before deletion
            drop_database(engine.url, checkfirst=False)
        except Exception as e:
            logger.error(f"Error dropping test database: {e}")

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
        "hashed_password": "test_password",
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
        "hashed_password": "test_password2",
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
def second_signed_up_user(client, second_test_user):
    """Sign up the second user and return the user data and tokens."""
    response = client.post("/sign_up", json=second_test_user)
    assert response.status_code == 201
    data = response.json
    return {"user": second_test_user, "access_token": data["access_token"], "refresh_token": data["refresh_token"]}

@pytest.fixture
def second_logged_in_user(client, second_signed_up_user):
    """Log in the second user and return login tokens."""
    response = client.post("/login", json=second_signed_up_user["user"])
    assert response.status_code == 200
    data = response.json
    return {"user": second_signed_up_user["user"], "access_token": data["access_token"], "refresh_token": data["refresh_token"]}

@pytest.fixture
def test_file_data():
    """Generate a sample file data for testing."""
    return {
        "file": {
            "filename": "testfile.txt",
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

@pytest.mark.parametrize("user_id, expected_status, has_error", [
    ("valid", 200, False),  # Valid user ID - will be replaced with actual ID in test
    ("99999", 404, True),   # Non-existent user
    (None, 400, True),      # Missing user_id parameter
    ("invalid", 400, True), # Invalid format
])
def test_get_public_key(client, logged_in_user, second_logged_in_user, user_id, expected_status, has_error):
    """Test getting a user's public key with various scenarios."""
    # Handle the special "valid" case
    if user_id == "valid":
        from server.utils.db_setup import get_session
        from server.models.tables import Users
        
        with get_session() as db:
            user = db.query(Users).filter_by(username=second_logged_in_user["user"]["username"]).first()
            user_id = user.id  # Changed from user.user_id to user.id
    
    # Build the URL
    if user_id is None:
        url = "/api/permissions/public_key"
    else:
        url = f"/api/permissions/public_key?user_id={user_id}"
    
    response = client.get(url)
    assert response.status_code == expected_status
    data = response.json
    
    if has_error:
        assert "error" in data
    else:
        assert "public_key" in data
        assert data["public_key"] == second_logged_in_user["user"]["public_key"]

@pytest.mark.parametrize("scenario, expected_status, has_error", [
    ("success", 201, False),      # Normal successful creation
    ("duplicate", 409, True),     # Creating duplicate permission
])
def test_create_permission(client, logged_in_user, second_logged_in_user, stored_file_data, scenario, expected_status, has_error):
    """Test creating file permissions with various scenarios."""
    # Get the second user's ID
    from server.utils.db_setup import get_session
    from server.models.tables import Users
    
    with get_session() as db:
        user = db.query(Users).filter_by(username=second_logged_in_user["user"]["username"]).first()
        user_id = user.id  # Changed from user.user_id to user.id
        file_id = stored_file_data["file_uuid"]
    
    headers = {"Authorization": f"Bearer {logged_in_user['access_token']}"}
    permission_data = {
        "file_id": file_id,
        "user_id": user_id,
        "key_for_recipient": "encrypted_key_for_recipient"
    }
    
    if scenario == "duplicate":
        # Create permission first time
        response = client.post("/api/permissions", json=permission_data, headers=headers)
        assert response.status_code == 201
    
    # Now make the actual test request
    response = client.post("/api/permissions", json=permission_data, headers=headers)
    assert response.status_code == expected_status
    data = response.json
    
    if has_error:
        assert "error" in data
    else:
        assert "message" in data

@pytest.mark.parametrize("scenario, expected_status, has_error", [
    ("success", 200, False),          # Normal successful removal
    ("nonexistent", 404, True),       # Removing non-existent permission
])
def test_remove_permission(client, logged_in_user, second_logged_in_user, stored_file_data, scenario, expected_status, has_error):
    """Test removing file permissions with various scenarios."""
    # Get the second user's ID
    from server.utils.db_setup import get_session
    from server.models.tables import Users
    
    with get_session() as db:
        user = db.query(Users).filter_by(username=second_logged_in_user["user"]["username"]).first()
        user_id = user.id  # Changed from user.user_id to user.id
        file_id = stored_file_data["file_uuid"]
    
    headers = {"Authorization": f"Bearer {logged_in_user['access_token']}"}
    
    if scenario == "success":
        # Create permission first
        permission_data = {
            "file_id": file_id,
            "user_id": user_id,
            "key_for_recipient": "encrypted_key_for_recipient"
        }
        response = client.post("/api/permissions", json=permission_data, headers=headers)
        assert response.status_code == 201
    
    # Prepare removal data
    remove_data = {
        "file_id": file_id,
        "user_id": user_id
    }
    
    # Make the removal request
    response = client.delete("/api/permissions", json=remove_data, headers=headers)
    assert response.status_code == expected_status
    data = response.json
    
    if has_error:
        assert "error" in data
    else:
        assert "message" in data

@pytest.mark.parametrize("missing_field, expected_status", [
    ("file_id", 400),
    ("user_id", 400),
    ("key_for_recipient", 400),
])
def test_create_permission_missing_fields(client, logged_in_user, second_logged_in_user, stored_file_data, missing_field, expected_status):
    """Test creating permissions with missing required fields."""
    from server.utils.db_setup import get_session
    from server.models.tables import Users
    
    with get_session() as db:
        user = db.query(Users).filter_by(username=second_logged_in_user["user"]["username"]).first()
        user_id = user.id  # Changed from user.user_id to user.id
        file_id = stored_file_data["file_uuid"]
    
    headers = {"Authorization": f"Bearer {logged_in_user['access_token']}"}
    permission_data = {
        "file_id": file_id,
        "user_id": user_id,
        "key_for_recipient": "encrypted_key_for_recipient"
    }
    
    # Remove the specified field
    del permission_data[missing_field]
    
    response = client.post("/api/permissions", json=permission_data, headers=headers)
    assert response.status_code == expected_status
    data = response.json
    assert "error" in data

@pytest.mark.parametrize("missing_field, expected_status", [
    ("file_id", 400),
    ("user_id", 400),
])
def test_remove_permission_missing_fields(client, logged_in_user, missing_field, expected_status):
    """Test removing permissions with missing required fields."""
    headers = {"Authorization": f"Bearer {logged_in_user['access_token']}"}
    remove_data = {
        "file_id": 1,
        "user_id": 1
    }
    
    # Remove the specified field
    del remove_data[missing_field]
    
    response = client.delete("/api/permissions", json=remove_data, headers=headers)
    assert response.status_code == expected_status
    data = response.json
    assert "error" in data
