import pytest
import uuid
import base64
import os
import shutil
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
    
    # Clean up uploaded files
    uploads_dir = "uploads"
    if os.path.exists(uploads_dir):
        try:
            shutil.rmtree(uploads_dir)
            logger.info("Cleaned up uploads directory")
        except Exception as e:
            logger.error(f"Error cleaning up uploads directory: {e}")
    
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
        "password": "test_password",
        "public_key": unique_public_key,
        "salt": "test_salt"
    }

@pytest.fixture
def signed_up_user(client, test_user):
    """Sign up a user and return the user data and tokens."""
    response = client.post("/sign_up", json=test_user)
    if response.status_code != 201:
        raise RuntimeError(f"Failed to sign up user: {response.json}")
    data = response.json
    return {
        "user": test_user,
        "access_token": data["access_token"],
        "refresh_token": data["refresh_token"],
        "response": response
    }

@pytest.fixture
def logged_in_user(client, signed_up_user):
    """Log in the signed-up user and return login tokens."""
    response = client.post("/login", json=signed_up_user["user"])
    if response.status_code != 200:
        raise RuntimeError(f"Failed to log in user: {response.json}")
    data = response.json
    return {
        "user": signed_up_user["user"],
        "access_token": data["access_token"],
        "refresh_token": data["refresh_token"],
        "response": response
    }

@pytest.fixture
def test_file_data():
    """Generate a sample file data for testing."""
    file_content = b"test file content"
    encoded_content = base64.b64encode(file_content).decode('utf-8')
    return {
        "file": {
            "filename": "testfile.txt",
            "contents": encoded_content
        },
        "metadata": {
            "size": len(file_content),
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
        raise RuntimeError(f"Failed to upload file: {response.json}")
    data = response.json
    return {
        "uuid": data["uuid"],
        "filename": test_file_data["file"]["filename"],
        "response": response
    }

def test_file_upload(client, logged_in_user, setup_test_db):
    """Test file upload functionality."""
    file_content = b"test file content"
    encoded_content = base64.b64encode(file_content).decode('utf-8')
    
    headers = {
        "Authorization": f"Bearer {logged_in_user['access_token']}",
        "Content-Type": "application/json"
    }
    file_data = {
        "file": {
            "filename": "testfile.txt",
            "contents": encoded_content
        },
        "metadata": {
            "size": len(file_content),
            "format": "txt"
        }
    }
    response = client.post("/api/files/upload", headers=headers, json=file_data)
    assert response.status_code == 201
    data = response.json
    assert "uuid" in data
    assert "message" in data

def test_list_files(client, logged_in_user, setup_test_db):
    """Test listing files for the logged-in user."""
    headers = {
        "Authorization": f"Bearer {logged_in_user['access_token']}"
    }
    response = client.get("/api/files/", headers=headers)
    assert response.status_code == 200
    data = response.json
    assert "owned_files" in data
    assert "shared_files" in data

def test_get_file(client, logged_in_user, stored_file_data, setup_test_db):
    """Test retrieving a specific file by UUID."""
    headers = {
        "Authorization": f"Bearer {logged_in_user['access_token']}"
    }
    response = client.get(f"/api/files/{stored_file_data['uuid']}", headers=headers)
    assert response.status_code == 200
    data = response.json
    assert "encrypted_file" in data

def test_delete_file(client, logged_in_user, stored_file_data, setup_test_db):
    """Test deleting a file by UUID."""
    headers = {
        "Authorization": f"Bearer {logged_in_user['access_token']}"
    }
    response = client.delete(f"/api/files/{stored_file_data['uuid']}", headers=headers)
    assert response.status_code == 200
    data = response.json
    assert "message" in data