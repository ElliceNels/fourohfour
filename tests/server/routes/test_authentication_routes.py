import pytest
import uuid
import logging
from flask.testing import FlaskClient
from sqlalchemy_utils import database_exists, drop_database
from server.utils.db_setup import setup_db, teardown_db
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
    db_name = "test_database"
    engine = setup_db(db_name)
    logger.info("Test database setup complete.")
    yield

    teardown_db(db_name, engine=engine, remove_db=True)

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

def test_sign_up(client: FlaskClient, test_user):
    """Test user sign-up."""
    response = client.post("/sign_up", json=test_user)
    print(f"Sign-up response: {response.json}")
    assert response.status_code == 201
    assert "access_token" in response.json
    assert "refresh_token" in response.json

def test_login(client: FlaskClient, test_user):
    """Test user login."""
    client.post("/sign_up", json=test_user)  # Ensure user exists
    response = client.post("/login", json=test_user)
    assert response.status_code == 200
    assert "access_token" in response.json
    assert "refresh_token" in response.json

def test_refresh_token(client: FlaskClient, logged_in_user):
    """Test refreshing access token."""
    refresh_token = logged_in_user["refresh_token"]
    
    response = client.post("/refresh", json={"refresh_token": refresh_token})
    assert response.status_code == 200
    assert "access_token" in response.json

def test_change_password(client: FlaskClient, logged_in_user):
    """Test changing password."""
    new_password_data = {"new_password": "new_test_password"}

    headers = {"Authorization": f"Bearer {logged_in_user['access_token']}"}
    response = client.post("/change_password", json=new_password_data, headers=headers)
    assert response.status_code == 200
    assert response.json["message"] == "Password updated successfully"

def test_logout(client: FlaskClient, logged_in_user):
    """Test user logout."""
    headers = {
        "Authorization": f"Bearer {logged_in_user['access_token']}",
        "X-Refresh-Token": logged_in_user["refresh_token"]
    }
    response = client.post("/logout", headers=headers)
    assert response.status_code == 200
    assert response.json["message"] == "Logged out successfully"

def test_delete_account(client: FlaskClient, logged_in_user):
    """Test deleting account."""
    headers = {"Authorization": f"Bearer {logged_in_user['access_token']}"}
    response = client.post(
        "/delete_account",
        json={"username": logged_in_user["user"]["username"]},
        headers=headers
    )
    assert response.status_code == 200
    assert response.json["message"] == "Account deleted successfully"

def test_get_public_key(client: FlaskClient, logged_in_user):
    """Test getting public key."""
    headers = {"Authorization": f"Bearer {logged_in_user['access_token']}"}
    username = logged_in_user["user"]["username"]
    response = client.get(f"/get_public_key?username={username}", headers=headers)
    assert response.status_code == 200
    assert "public_key" in response.json
    assert response.json["public_key"] == logged_in_user["user"]["public_key"]

def test_get_current_user(client: FlaskClient, logged_in_user):
    """Test getting current user information."""
    headers = {"Authorization": f"Bearer {logged_in_user['access_token']}"}
    response = client.get("/get_current_user", headers=headers)
    assert response.status_code == 200
    assert response.json["username"] == logged_in_user["user"]["username"]

def test_db_tables_exist(setup_test_db):
    """Ensure tables exist after setup."""
    from server.models.tables import Users
    from server.utils.db_setup import get_session
    with get_session() as db:
        # Should not raise
        db.query(Users).all()

def test_db_is_clean_after_setup(setup_test_db):
    """Ensure the Users table is empty after setup."""
    from server.models.tables import Users
    from server.utils.db_setup import get_session
    with get_session() as db:
        assert db.query(Users).count() == 0