import pytest
import uuid
import logging
from flask.testing import FlaskClient
from sqlalchemy_utils import database_exists, drop_database
from server.utils.db_setup import setup_db, teardown_db
from server.app import create_app
from server.models.tables import Base
import base64
from datetime import datetime, UTC, timedelta
from server.utils.auth import hash_password

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
    
    # Clean up any existing data
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    
    yield

    # Clean up after tests
    Base.metadata.drop_all(bind=engine)
    teardown_db(db_name, engine=engine, remove_db=True)
    logger.info("Test database teardown complete.")

@pytest.fixture
def client(app_fixture):
    """Create a test client using Flask's test framework."""
    with app_fixture.test_client() as client:
        yield client

@pytest.fixture
def test_user():
    """Generate a unique test user for each run with valid base64 cryptographic keys."""
    unique_username = f"test_user_{uuid.uuid4().hex[:8]}"
    # Generate a random 32-byte value and encode as base64 for public key
    random_bytes = uuid.uuid4().bytes + uuid.uuid4().bytes
    unique_public_key = base64.b64encode(random_bytes).decode()
    # Generate SPK and signature (mock values for testing)
    spk_bytes = uuid.uuid4().bytes + uuid.uuid4().bytes
    unique_spk = base64.b64encode(spk_bytes).decode()  # Encode as string for JSON
    signature_bytes = uuid.uuid4().bytes + uuid.uuid4().bytes
    unique_spk_signature = base64.b64encode(signature_bytes).decode()  # Encode as string for JSON
    
    return {
        "username": unique_username,
        "password": "test_password",
        "public_key": unique_public_key,
        "spk": unique_spk,
        "spk_signature": unique_spk_signature,
        "salt": "test_salt"
    }

@pytest.fixture
def signed_up_user(client, test_user):
    """Sign up a user and return the user data and tokens."""
    from server.models.tables import Users, OTPK
    from server.utils.db_setup import get_session
    from server.utils.auth import hash_password
    
    current_time = datetime.now(UTC)
    with get_session() as db:
        user = Users(
            username=test_user["username"],
            password=hash_password(test_user["password"]),  # Hash the password
            public_key=test_user["public_key"],
            spk=test_user["spk"],
            spk_signature=test_user["spk_signature"],
            salt=test_user["salt"].encode('utf-8'),  # Encode salt as UTF-8 bytes
            spk_updated_at=current_time,
            updated_at=current_time,
            created_at=current_time
        )
        db.add(user)
        db.flush()  # Ensure user.id is available
        
        # Add 10 OTPKs for the user
        test_otpks = [
            base64.b64encode(f"test_otpk_{i}".encode()).decode()
            for i in range(10)
        ]
        
        for otpk in test_otpks:
            new_otpk = OTPK(
                user_id=user.id,
                key=otpk,
                used=0,
                created_at=current_time,
                updated_at=current_time
            )
            db.add(new_otpk)
        
        db.commit()
    
    # Get tokens by logging in
    response = client.post("/login", json=test_user)
    assert response.status_code == 200
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
    # Create user with timezone-aware datetime
    from server.models.tables import Users, OTPK
    from server.utils.db_setup import get_session
    from server.utils.auth import hash_password
    from datetime import timedelta
    
    current_time = datetime.now(UTC)
    spk_updated_at = current_time - timedelta(days=3)  # Set SPK to 3 days old
    with get_session() as db:
        user = Users(
            username=test_user["username"],
            password=hash_password(test_user["password"]),  # Hash the password
            public_key=test_user["public_key"],
            spk=test_user["spk"],
            spk_signature=test_user["spk_signature"],
            salt=test_user["salt"].encode('utf-8'),  # Encode salt as UTF-8 bytes
            spk_updated_at=spk_updated_at,  # Use the older time for SPK
            updated_at=current_time,
            created_at=current_time
        )
        db.add(user)
        db.flush()  # Ensure user.id is available
        
        # Add 10 OTPKs for the user
        test_otpks = [
            base64.b64encode(f"test_otpk_{i}".encode()).decode()
            for i in range(10)
        ]
        
        for otpk in test_otpks:
            new_otpk = OTPK(
                user_id=user.id,
                key=otpk,
                used=0,
                created_at=current_time,
                updated_at=current_time
            )
            db.add(new_otpk)
        
        db.commit()
    
    response = client.post("/login", json=test_user)
    assert response.status_code == 200
    data = response.json
    assert "access_token" in data
    assert "refresh_token" in data
    assert "unused_otpk_count" in data
    assert "spk_outdated" in data
    assert "otpk_count_low" in data
    assert isinstance(data["spk_outdated"], bool)
    assert isinstance(data["otpk_count_low"], bool)

def test_refresh_token(client: FlaskClient, logged_in_user):
    """Test refreshing access token."""
    refresh_token = logged_in_user["refresh_token"]
    
    response = client.post("/refresh", json={"refresh_token": refresh_token})
    assert response.status_code == 200
    assert "access_token" in response.json

def test_change_password(client: FlaskClient, logged_in_user):
    """Test changing password."""
    new_password_data = {
        "new_password": "new_test_password",
        "salt": "new_test_salt"  # Send as string, route will convert to bytes
    }

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

#TODO when we can add otpks we should test the count of OTPKs
def test_count_otpk(client: FlaskClient, logged_in_user):
    """Test counting one-time prekeys (OTPKs)."""
    headers = {"Authorization": f"Bearer {logged_in_user['access_token']}"}
    response = client.get("/count_otpk", headers=headers)
    assert response.status_code == 200
    assert "otpk_count" in response.json
    assert isinstance(response.json["otpk_count"], int)
    assert response.json["otpk_count"] >= 0

def test_add_otpks(client: FlaskClient, logged_in_user):
    """Test adding one-time prekeys (OTPKs)."""
    headers = {"Authorization": f"Bearer {logged_in_user['access_token']}"}
    
    # First get initial count
    initial_count_response = client.get("/count_otpk", headers=headers)
    assert initial_count_response.status_code == 200
    initial_count = initial_count_response.json["otpk_count"]
    
    # Generate some test OTPKs (base64 encoded)
    test_otpks = [
        base64.b64encode(b"test_otpk_1").decode(),
        base64.b64encode(b"test_otpk_2").decode(),
        base64.b64encode(b"test_otpk_3").decode()
    ]
    
    # Add the OTPKs
    add_response = client.post("/add_otpks", json={"otpks": test_otpks}, headers=headers)
    assert add_response.status_code == 201
    
    # Get new count and verify it increased by the number of OTPKs we added
    new_count_response = client.get("/count_otpk", headers=headers)
    assert new_count_response.status_code == 200
    new_count = new_count_response.json["otpk_count"]
    
    assert new_count == initial_count + len(test_otpks)

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

def test_retrieve_key_bundle(client: FlaskClient, logged_in_user):
    """Test retrieving a key bundle."""
    headers = {"Authorization": f"Bearer {logged_in_user['access_token']}"}
    
    # Clear existing OTPKs first
    from server.models.tables import OTPK
    from server.utils.db_setup import get_session
    
    with get_session() as db:
        db.query(OTPK).delete()
        db.commit()
    
    # First add some OTPKs
    test_otpks = [
        base64.b64encode(b"test_otpk_1").decode(),
        base64.b64encode(b"test_otpk_2").decode(),
        base64.b64encode(b"test_otpk_3").decode()
    ]
    
    # Add the OTPKs
    add_response = client.post("/add_otpks", json={"otpks": test_otpks}, headers=headers)
    assert add_response.status_code == 201
    
    # Get a key bundle
    username = logged_in_user["user"]["username"]
    get_response = client.get(f"/retrieve_key_bundle?username={username}", headers=headers)
    assert get_response.status_code == 200
    assert "otpk" in get_response.json
    assert "spk" in get_response.json
    assert "spk_signature" in get_response.json
    assert "updatedAt" in get_response.json
    assert get_response.json["otpk"] in test_otpks
    assert get_response.json["spk"] == logged_in_user["user"]["spk"]
    assert get_response.json["spk_signature"] == logged_in_user["user"]["spk_signature"]
    
    # Verify the OTPK was marked as used by trying to get it again
    # It should return a different OTPK
    get_response_2 = client.get(f"/retrieve_key_bundle?username={username}", headers=headers)
    assert get_response_2.status_code == 200
    assert "otpk" in get_response_2.json
    assert get_response_2.json["otpk"] in test_otpks
    assert get_response_2.json["otpk"] != get_response.json["otpk"]

def test_update_spk(client: FlaskClient, logged_in_user):
    """Test updating signed pre key."""
    headers = {"Authorization": f"Bearer {logged_in_user['access_token']}"}
    
    # Generate new SPK and signature
    new_spk = base64.b64encode(uuid.uuid4().bytes + uuid.uuid4().bytes).decode()
    new_signature = base64.b64encode(uuid.uuid4().bytes + uuid.uuid4().bytes).decode()
    
    # Update SPK
    update_data = {
        "spk": new_spk,
        "spk_signature": new_signature
    }
    response = client.post("/update_spk", json=update_data, headers=headers)
    assert response.status_code == 200
    assert response.json["message"] == "Signed Pre Key updated successfully"
    
    # Verify the update by querying the database directly
    from server.utils.db_setup import get_session
    from server.models.tables import Users
    
    with get_session() as db:
        user = db.query(Users).filter_by(username=logged_in_user["user"]["username"]).first()
        assert user is not None
        assert user.spk == new_spk
        assert user.spk_signature == new_signature
