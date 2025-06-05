import pytest
import uuid
import logging
import os
from flask.testing import FlaskClient
from sqlalchemy_utils import database_exists, drop_database
from server.utils.db_setup import setup_db, get_session, teardown_db
from server.app import create_app
from server.models.tables import Base, Users, Files, OTPK, FilePermissions
import base64
from datetime import datetime, UTC
from server.utils.auth import hash_password

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
    unique_username = f"test_user_{uuid.uuid4().hex[:8]}"
    # Generate random bytes for cryptographic keys
    random_bytes = uuid.uuid4().bytes + uuid.uuid4().bytes
    unique_public_key = base64.b64encode(random_bytes).decode()
    
    # Generate spk and spk_signature
    spk_bytes = uuid.uuid4().bytes + uuid.uuid4().bytes
    spk = base64.b64encode(spk_bytes).decode()
    signature_bytes = uuid.uuid4().bytes + uuid.uuid4().bytes
    spk_signature = base64.b64encode(signature_bytes).decode()
    
    return {
        "username": unique_username,
        "password": "test_password",
        "public_key": unique_public_key,
        "salt": "test_salt",
        "spk": spk,
        "spk_signature": spk_signature
    }

@pytest.fixture
def second_test_user():
    """Generate a second unique test user for permission sharing tests."""
    unique_username = f"test_user2_{uuid.uuid4().hex[:8]}"
    # Generate random bytes for cryptographic keys
    random_bytes = uuid.uuid4().bytes + uuid.uuid4().bytes
    unique_public_key = base64.b64encode(random_bytes).decode()
    
    # Generate spk and spk_signature
    spk_bytes = uuid.uuid4().bytes + uuid.uuid4().bytes
    spk = base64.b64encode(spk_bytes).decode()
    signature_bytes = uuid.uuid4().bytes + uuid.uuid4().bytes
    spk_signature = base64.b64encode(signature_bytes).decode()
    
    return {
        "username": unique_username,
        "password": "test_password2",
        "public_key": unique_public_key,
        "salt": "test_salt2",
        "spk": spk,
        "spk_signature": spk_signature
    }

@pytest.fixture
def third_test_user():
    """Generate a third unique test user for permission sharing tests."""
    unique_username = f"test_user3_{uuid.uuid4().hex[:8]}"
    # Generate random bytes for cryptographic keys
    random_bytes = uuid.uuid4().bytes + uuid.uuid4().bytes
    unique_public_key = base64.b64encode(random_bytes).decode()
    
    # Generate spk and spk_signature
    spk_bytes = uuid.uuid4().bytes + uuid.uuid4().bytes
    spk = base64.b64encode(spk_bytes).decode()
    signature_bytes = uuid.uuid4().bytes + uuid.uuid4().bytes
    spk_signature = base64.b64encode(signature_bytes).decode()
    
    return {
        "username": unique_username,
        "password": "test_password3",
        "public_key": unique_public_key,
        "salt": "test_salt3",
        "spk": spk,
        "spk_signature": spk_signature
    }

@pytest.fixture
def signed_up_user(client, test_user):
    """Sign up a user and return the user data and tokens."""
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
            "size": len(file_content),  # Use actual file size instead of hardcoded value
            "format": "txt"
        }
    }

@pytest.fixture
def second_signed_up_user(client, second_test_user):
    """Sign up the second user and return the user data."""
    # Sign up the user
    response = client.post("/sign_up", json=second_test_user)
    assert response.status_code == 201
    
    # Create OTPKs for the user
    with get_session() as db:
        user = db.query(Users).filter_by(username=second_test_user["username"]).first()
        assert user is not None
        
        # Add 10 OTPKs for the user
        current_time = datetime.now(UTC)
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
    
    return second_test_user

@pytest.fixture
def third_signed_up_user(client, third_test_user):
    """Sign up the third user and return the user data."""
    # Sign up the user
    response = client.post("/sign_up", json=third_test_user)
    assert response.status_code == 201
    
    # Create OTPKs for the user
    with get_session() as db:
        user = db.query(Users).filter_by(username=third_test_user["username"]).first()
        assert user is not None
        
        # Add 10 OTPKs for the user
        current_time = datetime.now(UTC)
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
    
    return third_test_user

@pytest.fixture
def stored_file_data(logged_in_user, test_file_data, client):
    """Upload a file and return its metadata."""
    headers = {
        "Authorization": f"Bearer {logged_in_user['access_token']}",
        "Content-Type": "application/json"
    }
    response = client.post("/api/files/upload", headers=headers, json=test_file_data)
    assert response.status_code == 201
    
    data = response.json
    file_data = {
        "file_uuid": data["uuid"],
        "message": data["message"]
    }
    
    yield file_data
    
    # Cleanup: Delete the file after the test
    try:
        with get_session() as db:
            file = db.query(Files).filter_by(uuid=file_data["file_uuid"]).first()
            if file:
                # Delete the file from disk
                if os.path.exists(file.path):
                    os.remove(file.path)
                # Delete the file from database
                db.delete(file)
                db.commit()
    except Exception as e:
        logger.error(f"Error cleaning up test file: {str(e)}")

@pytest.mark.parametrize("expected_status, include_key, include_file, include_user_id, is_owner, is_self_removal", [
    (SUCCESS, True, True, True, True, False),  # Success: owner removing permission
    (SUCCESS, True, True, True, False, True),  # Success: user removing their own permission
    (NOT_FOUND, True, True, True, True, False),         # Error: permission not found
    (BAD_REQUEST, True, False, True, True, False),      # Error: missing file_uuid
    (BAD_REQUEST, True, True, False, True, False),      # Error: missing username
    (NOT_FOUND, True, True, True, False, False),        # Error: file not found
    (FORBIDDEN, True, True, True, False, False),        # Error: not owner and not self
])
def test_remove_permission(client, logged_in_user, second_signed_up_user, third_signed_up_user, stored_file_data, expected_status, include_key, include_file, include_user_id, is_owner, is_self_removal):
    """Test removing file permissions with various scenarios."""
    headers = {"Authorization": f"Bearer {logged_in_user['access_token']}"}
    
    # Create permission for both SUCCESS and FORBIDDEN cases
    if expected_status in (SUCCESS, FORBIDDEN):
        # Create permission first
        key_bytes = uuid.uuid4().bytes + uuid.uuid4().bytes
        otpk_bytes = uuid.uuid4().bytes + uuid.uuid4().bytes
        ephemeral_key_bytes = uuid.uuid4().bytes + uuid.uuid4().bytes
        
        # For self-removal case, create permission for logged-in user
        # For owner case, create permission for second user
        # For forbidden case, create permission for second user (logged-in user is neither owner nor permission holder)
        target_username = logged_in_user["user"]["username"] if is_self_removal else second_signed_up_user["username"]
        
        permission_data = {
            "file_uuid": stored_file_data["file_uuid"],
            "username": target_username,
            "key_for_recipient": base64.b64encode(key_bytes).decode(),
            "otpk": base64.b64encode(otpk_bytes).decode(),
            "ephemeral_key": base64.b64encode(ephemeral_key_bytes).decode()
        }
        response = client.post("/api/permissions", json=permission_data, headers=headers)
        assert response.status_code == CREATED
    
    # Prepare removal data
    remove_data = {}
    
    if include_file:
        # For NOT_FOUND test case, use a random UUID
        if expected_status == NOT_FOUND and not is_owner:
            remove_data["file_uuid"] = str(uuid.uuid4())
        else:
            remove_data["file_uuid"] = stored_file_data["file_uuid"]
    
    if include_key:
        key_bytes = uuid.uuid4().bytes + uuid.uuid4().bytes
        remove_data["key_for_recipient"] = base64.b64encode(key_bytes).decode()
    
    if include_user_id:
        # For forbidden case, we want to try to remove someone else's permission
        # For self-removal case, use the logged-in user's username
        # For owner case, use the second user's username
        if expected_status == FORBIDDEN:
            # Try to remove the second user's permission (which exists) with the third user (who is neither owner nor permission holder)
            remove_data["username"] = second_signed_up_user["username"]
            # Get third user's token
            response = client.post("/login", json=third_signed_up_user)
            assert response.status_code == 200
            third_user_token = response.json["access_token"]
            headers = {"Authorization": f"Bearer {third_user_token}"}
        else:
            remove_data["username"] = logged_in_user["user"]["username"] if is_self_removal else second_signed_up_user["username"]
    
    # Add debug logging
    logger.info(f"Test case: expected_status={expected_status}, is_owner={is_owner}, is_self_removal={is_self_removal}")
    logger.info(f"Logged in user: {logged_in_user['user']['username']}")
    logger.info(f"Second user: {second_signed_up_user['username']}")
    logger.info(f"Remove data: {remove_data}")
    
    # Make the removal request
    response = client.delete(f"/api/permissions/{remove_data['file_uuid']}/{remove_data['username']}", headers=headers)
    assert response.status_code == expected_status

@pytest.mark.parametrize("expected_status, include_key, include_file, include_user_id, is_owner", [
    (CREATED, True, True, True, True),  # Success: all fields included
    (CONFLICT, True, True, True, True),  # Conflict: all fields included
    (BAD_REQUEST, True, False, True, True),      # Error: missing file_uuid
    (BAD_REQUEST, True, True, False, True),      # Error: missing username
    (BAD_REQUEST, False, True, True, True),      # Error: missing key_for_recipient
    (NOT_FOUND, True, True, True, False),        # Error: file not found
])
def test_create_permission(client, logged_in_user, second_signed_up_user, stored_file_data, expected_status, include_key, include_file, include_user_id, is_owner):
    """Test creating file permissions with various scenarios."""
    headers = {"Authorization": f"Bearer {logged_in_user['access_token']}"}
    permission_data = {}
    
    if include_file:
        permission_data["file_uuid"] = uuid.uuid4() if not is_owner else stored_file_data["file_uuid"]
    
    if include_key:
        # Generate random bytes for keys and encode as base64
        key_bytes = uuid.uuid4().bytes + uuid.uuid4().bytes
        otpk_bytes = uuid.uuid4().bytes + uuid.uuid4().bytes
        ephemeral_key_bytes = uuid.uuid4().bytes + uuid.uuid4().bytes
        
        permission_data["key_for_recipient"] = base64.b64encode(key_bytes).decode()
        permission_data["otpk"] = base64.b64encode(otpk_bytes).decode()
        permission_data["ephemeral_key"] = base64.b64encode(ephemeral_key_bytes).decode()
    
    if include_user_id:
        permission_data["username"] = second_signed_up_user["username"]
    
    if expected_status == CONFLICT:
        # Create permission first time
        response = client.post("/api/permissions", json=permission_data, headers=headers)
        assert response.status_code == CREATED
    
    # Now make the actual test request
    response = client.post("/api/permissions", json=permission_data, headers=headers)
    assert response.status_code == expected_status

@pytest.mark.parametrize("expected_status, is_owner", [
    (SUCCESS, True),           # Success: user is owner
    (NOT_FOUND, False),        # Error: file not found
])
def test_get_permissions(client, logged_in_user, second_signed_up_user, stored_file_data, expected_status, is_owner):
    """Test getting file permissions."""
    headers = {"Authorization": f"Bearer {logged_in_user['access_token']}"}
    
    # Create a permission first so we have something to retrieve
    key_bytes = uuid.uuid4().bytes + uuid.uuid4().bytes
    otpk_bytes = uuid.uuid4().bytes + uuid.uuid4().bytes
    ephemeral_key_bytes = uuid.uuid4().bytes + uuid.uuid4().bytes
    
    permission_data = {
        "file_uuid": stored_file_data["file_uuid"],
        "username": second_signed_up_user["username"],
        "key_for_recipient": base64.b64encode(key_bytes).decode(),
        "otpk": base64.b64encode(otpk_bytes).decode(),
        "ephemeral_key": base64.b64encode(ephemeral_key_bytes).decode()
    }
    response = client.post("/api/permissions", json=permission_data, headers=headers)
    assert response.status_code == CREATED
    
    # Make the GET request
    file_uuid = stored_file_data["file_uuid"] if is_owner else str(uuid.uuid4())
    response = client.get(f"/api/permissions/{file_uuid}", headers=headers)
    assert response.status_code == expected_status
    
    if expected_status == SUCCESS:
        data = response.json
        assert "permissions" in data
        assert isinstance(data["permissions"], list)
        assert len(data["permissions"]) > 0
        assert "username" in data["permissions"][0]
