import pytest
import uuid
from sqlalchemy_utils import database_exists, drop_database
from server.utils.db_setup import setup_db
from server.app import create_app
from server.models.tables import Base
import logging

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
    engine = setup_db("test_file_database")
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
        "encrypted_file": (b"test file content", "testfile.txt"),
        "metadata": '{"size": 1234, "format": "txt"}'
    }

@pytest.fixture
def stored_file_data(logged_in_user, test_file_data, client):
    """Upload a file and return its metadata."""
    headers = {
        "Authorization": f"Bearer {logged_in_user['access_token']}",
        "Content-Type": "multipart/form-data"
    }
    response = client.post("/api/files/upload", headers=headers, data=test_file_data)
    assert response.status_code == 201
    data = response.json
    return {
        "file_uuid": data["file_uuid"],
        "file_path": data["file_path"],
        "file_size": data["file_size"],
        "format": data["format"],
        "filename": data["filename"]
    }

def test_file_upload(client, logged_in_user):
    """Test file upload functionality."""
    headers = {
        "Authorization": f"Bearer {logged_in_user['access_token']}",
        "Content-Type": "multipart/form-data"
    }
    file_data = {
        "encrypted_file": (b"test file content", "testfile.txt"),
        "metadata": '{"size": 1234, "format": "txt"}'
    }
    response = client.post("/api/files/upload", headers=headers, data=file_data)
    assert response.status_code == 201
    data = response.json
    assert "file_uuid" in data
    assert "file_path" in data
    assert "file_size" in data
    assert data["file_size"] == 1234
    assert data["format"] == "txt"
    assert data["filename"] == "testfile.txt"


def test_list_files(client, logged_in_user):
    """Test listing files for the logged-in user."""
    headers = {
        "Authorization": f"Bearer {logged_in_user['access_token']}"
    }
    response = client.get("/api/files/", headers=headers)
    assert response.status_code == 200
    data = response.json
    assert "owned_files" in data
    assert "shared_files" in data

def test_get_file(client, logged_in_user, stored_file_data):
    """Test retrieving a specific file by UUID."""
    headers = {
        "Authorization": f"Bearer {logged_in_user['access_token']}"
    }
    response = client.get(f"/api/files/{stored_file_data['file_uuid']}", headers=headers)
    assert response.status_code == 200
    data = response.json
    assert data["file_uuid"] == stored_file_data["file_uuid"]
    assert data["filename"] == stored_file_data["filename"]
    assert data["file_size"] == stored_file_data["file_size"]
    assert data["format"] == stored_file_data["format"]
    assert "encrypted_file" in data  # Ensure file content is returned
    assert data["encrypted_file"] == stored_file_data["encrypted_file"]  # Check file content matches
    assert data["uploaded_at"] is not None  # Ensure timestamp is present
    assert data["is_owner"] is True  # Check ownership status

def test_delete_file(client, logged_in_user, stored_file_data):
    """Test deleting a file by UUID."""
    headers = {
        "Authorization": f"Bearer {logged_in_user['access_token']}"
    }
    response = client.delete(f"/api/files/{stored_file_data['file_uuid']}", headers=headers)
    assert response.status_code == 204  # No content on successful deletion
    response = client.post("/api/files/upload", headers=headers, data=stored_file_data)