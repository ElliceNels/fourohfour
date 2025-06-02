import pytest
import logging
from sqlalchemy import text
from datetime import datetime, UTC, timedelta
import uuid
from sqlalchemy.exc import IntegrityError, DataError
from server.config import config
from server.utils.auth import hash_password
from server.utils.db_setup import setup_db, get_session, teardown_db
from server.models.tables import Users, Files, FilePermissions, FileMetadata
import base64

logger = logging.getLogger(__name__)

# Fixtures & Setup

@pytest.fixture(scope="session")
def db_check():
    """Verify database connection and configuration.
    
    This fixture ensures the database is properly set up and connected
    to the correct database before running tests. It also tears down the DB after tests."""
    chosen_db = "conn_test_db"
    engine = setup_db(chosen_db)
    with get_session() as session:
        db_name = session.execute(text("SELECT DATABASE()")).scalar()
        assert db_name == chosen_db
        logger.info(f"Connected to database: {db_name}")
    yield True
    teardown_db(chosen_db, engine=engine, remove_db=True)

@pytest.fixture(scope="function")
def db_session(db_check):
    with get_session() as session:
        try:
            yield session
        finally:
            try:
                # Delete in order to respect foreign key constraints
                session.query(FilePermissions).delete()
                session.query(FileMetadata).delete()
                session.query(Files).delete()
                session.query(Users).delete()
                session.commit()
                
                # Verify cleanup was successful
                assert session.query(FilePermissions).count() == 0, "FilePermissions cleanup failed"
                assert session.query(FileMetadata).count() == 0, "FileMetadata cleanup failed"
                assert session.query(Files).count() == 0, "Files cleanup failed"
                assert session.query(Users).count() == 0, "Users cleanup failed"
            except Exception as e:
                session.rollback()
                logger.error(f"Error during test cleanup: {str(e)}")
                raise

# Helpers

def create_user(session, username=None):
    """Create a test user with unique identifiers."""
    username = username or f"user_{uuid.uuid4().hex[:8]}"
    logger.info(f"Creating test user: {username}")
    
    # Generate random bytes for cryptographic keys
    spk_bytes = uuid.uuid4().bytes + uuid.uuid4().bytes
    spk = base64.b64encode(spk_bytes).decode()
    signature_bytes = uuid.uuid4().bytes + uuid.uuid4().bytes
    spk_signature = base64.b64encode(signature_bytes).decode()
    
    user = Users(
        username=username,
        password=hash_password("password"),
        salt=b"salt",
        public_key=f"public_key_{uuid.uuid4().hex[:8]}",
        spk=spk,  # Add base64 encoded spk
        spk_signature=spk_signature,  # Add base64 encoded spk_signature
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC)
    )
    session.add(user)
    session.commit()
    logger.debug(f"Created user with ID: {user.id}")
    return user

def create_file(session, owner, name=None):
    name = name or f"file_{uuid.uuid4().hex[:8]}.txt"
    path = f"/test/path/{name}"
    logger.info(f"Creating test file: {name} for user {owner.username}")
    file = Files(
        owner_id=owner.id,
        name=name,
        path=path,
        uploaded_at=datetime.now(UTC)
    )
    session.add(file)
    session.commit()
    logger.debug(f"Created file with ID: {file.id}")
    return file

def create_metadata(session, file, size=1024, format="txt"):
    logger.info(f"Creating metadata for file {file.name} (ID: {file.id})")
    metadata = FileMetadata(
        file_id=file.id,
        size=size,
        format=format,
        last_updated_at=datetime.now(UTC)
    )
    session.add(metadata)
    session.commit()
    logger.debug(f"Created metadata with size: {size} bytes")
    return metadata

def create_permission(session, file, user, encryption_key=b"encrypted_key"):
    logger.info(f"Creating permission for file {file.name} (ID: {file.id}) and user {user.username}")
    # Generate random bytes for ephemeral key and encode as base64
    ephemeral_bytes = uuid.uuid4().bytes + uuid.uuid4().bytes
    ephemeral_key = base64.b64encode(ephemeral_bytes).decode()
    
    # Convert encryption_key to base64 if it's bytes
    if isinstance(encryption_key, bytes):
        encryption_key = base64.b64encode(encryption_key).decode()
    
    permission = FilePermissions(
        file_id=file.id,
        user_id=user.id,
        encryption_key=encryption_key,
        ephemeral_key=ephemeral_key,  # Add base64 encoded ephemeral key
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC)
    )
    session.add(permission)
    session.commit()
    logger.debug(f"Created permission with ID: {permission.id}")
    return permission

# Tests

def test_create_and_fetch_user(db_session):
    logger.info("Testing user creation and fetch")
    user = create_user(db_session)
    fetched = db_session.query(Users).filter_by(id=user.id).first()
    assert fetched is not None
    assert fetched.username == user.username
    logger.debug(f"Successfully fetched user: {user.username}")

def test_update_user_password(db_session):
    logger.info("Testing password update")
    user = create_user(db_session)
    new_password = "new_password"
    hashed_password = hash_password(new_password)
    user.password = hashed_password
    user.updated_at = datetime.now(UTC) + timedelta(seconds=1)
    db_session.commit()
    logger.debug(f"Updated password for user: {user.username}")

    updated: Users = db_session.query(Users).filter_by(id=user.id).first()
    assert updated.password == hashed_password

def test_file_with_metadata(db_session):
    logger.info("Testing file creation with metadata")
    user = create_user(db_session)
    file = create_file(db_session, user)
    metadata = create_metadata(db_session, file)

    fetched_file = db_session.query(Files).filter_by(id=file.id).first()
    fetched_meta = db_session.query(FileMetadata).filter_by(file_id=file.id).first()
    assert fetched_file is not None
    assert fetched_meta.size == metadata.size
    assert fetched_meta.format == metadata.format
    logger.debug(f"Successfully verified file and metadata for: {file.name}")

def test_update_metadata(db_session):
    user = create_user(db_session)
    file = create_file(db_session, user)
    metadata = create_metadata(db_session, file)

    metadata.size = 2048
    metadata.last_updated_at = datetime.now(UTC) + timedelta(seconds=1)
    db_session.commit()

    updated = db_session.query(FileMetadata).filter_by(file_id=file.id).first()
    assert updated.size == 2048

def test_permission_lifecycle(db_session):
    user = create_user(db_session)
    file = create_file(db_session, user)
    permission = create_permission(db_session, file, user)

    # Generate new random bytes for updated keys
    new_encryption_bytes = uuid.uuid4().bytes + uuid.uuid4().bytes
    new_encryption_key = base64.b64encode(new_encryption_bytes).decode()
    new_ephemeral_bytes = uuid.uuid4().bytes + uuid.uuid4().bytes
    new_ephemeral_key = base64.b64encode(new_ephemeral_bytes).decode()
    
    permission.encryption_key = new_encryption_key
    permission.ephemeral_key = new_ephemeral_key
    permission.updated_at = datetime.now(UTC) + timedelta(seconds=1)
    db_session.commit()

    updated = db_session.query(FilePermissions).filter_by(id=permission.id).first()
    assert updated.encryption_key == new_encryption_key
    assert updated.ephemeral_key == new_ephemeral_key

def test_cascading_delete_user(db_session):
    logger.info("Testing cascading delete for user")
    user = create_user(db_session)
    file = create_file(db_session, user)
    create_metadata(db_session, file)
    other_user = create_user(db_session)
    create_permission(db_session, file, other_user)

    db_session.delete(user)
    db_session.commit()
    logger.debug(f"Deleted user: {user.username}")

    assert db_session.query(Users).filter_by(id=user.id).first() is None
    assert db_session.query(Files).filter_by(owner_id=user.id).first() is None
    assert db_session.query(FileMetadata).filter_by(file_id=file.id).first() is None
    assert db_session.query(FilePermissions).filter_by(file_id=file.id).first() is None
    assert db_session.query(Users).filter_by(id=other_user.id).first() is not None
    logger.debug("Verified cascading delete completed successfully")

def test_cascading_delete_file(db_session):
    user = create_user(db_session)
    file = create_file(db_session, user)
    create_metadata(db_session, file)
    create_permission(db_session, file, user)

    db_session.delete(file)
    db_session.commit()

    assert db_session.query(Files).filter_by(id=file.id).first() is None
    assert db_session.query(FileMetadata).filter_by(file_id=file.id).first() is None
    assert db_session.query(FilePermissions).filter_by(file_id=file.id).first() is None

# Unhappy Path Tests

def test_user_creation_with_missing_fields(db_session):
    """Test that creating a user with missing required fields fails."""
    logger.info("Testing user creation with missing fields")
    try:
        user = Users(
            username="test_user",  # Missing password, salt, public_key, spk, spk_signature
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC)
        )
        db_session.add(user)
        db_session.commit()
        pytest.fail("Expected IntegrityError was not raised")
    except IntegrityError as e:
        logger.debug(f"Caught expected IntegrityError: {str(e)}")
        pass
    finally:
        db_session.rollback()
        logger.debug("Rolled back transaction")

def test_duplicate_usernames_fail(db_session):
    """Test that creating users with duplicate usernames fails."""
    logger.info("Testing duplicate username prevention")
    username = "duplicate_user"
    create_user(db_session, username=username)
    
    try:
        create_user(db_session, username=username)
        pytest.fail("Expected IntegrityError was not raised")
    except IntegrityError as e:
        logger.debug(f"Caught expected IntegrityError for duplicate username: {str(e)}")
        pass
    finally:
        db_session.rollback()
        logger.debug("Rolled back transaction")

def test_duplicate_public_keys_fail(db_session):
    """Test that creating users with duplicate public keys fails."""
    public_key = "duplicate_key"
    # Generate random bytes for cryptographic keys
    spk_bytes = uuid.uuid4().bytes + uuid.uuid4().bytes
    spk = base64.b64encode(spk_bytes).decode()
    signature_bytes = uuid.uuid4().bytes + uuid.uuid4().bytes
    spk_signature = base64.b64encode(signature_bytes).decode()
    
    user1 = Users(
        username="user1",
        password=hash_password("password"),
        salt=b"salt",
        public_key=public_key,
        spk=spk,
        spk_signature=spk_signature,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC)
    )
    db_session.add(user1)
    db_session.commit()

    try:
        user2 = Users(
            username="user2",
            password=hash_password("password"),
            salt=b"salt",
            public_key=public_key,
            spk=spk,
            spk_signature=spk_signature,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC)
        )
        db_session.add(user2)
        db_session.commit()
        pytest.fail("Expected IntegrityError was not raised")
    except IntegrityError as e:
        logger.debug(f"Caught expected IntegrityError for duplicate public key: {str(e)}")
        pass
    finally:
        db_session.rollback()
        logger.debug("Rolled back transaction")

def test_file_with_nonexistent_user_fails(db_session):
    """Test that creating a file with a non-existent user fails."""
    try:
        file = Files(
            owner_id=99999,  # Non-existent user ID
            name="test.txt",
            path="/test/path/test.txt",
            uploaded_at=datetime.now(UTC)
        )
        db_session.add(file)
        db_session.commit()
        pytest.fail("Expected IntegrityError was not raised")
    except IntegrityError:
        pass
    finally:
        db_session.rollback()

def test_metadata_with_nonexistent_file_fails(db_session):
    """Test that creating metadata for a non-existent file fails."""
    try:
        metadata = FileMetadata(
            file_id=99999,  # Non-existent file ID
            size=1024,
            format="txt",
            last_updated_at=datetime.now(UTC)
        )
        db_session.add(metadata)
        db_session.commit()
        pytest.fail("Expected IntegrityError was not raised")
    except IntegrityError:
        pass
    finally:
        db_session.rollback()

def test_duplicate_file_metadata_fails(db_session):
    """Test that creating duplicate metadata for a file fails."""
    user = create_user(db_session)
    file = create_file(db_session, user)
    create_metadata(db_session, file)

    try:
        create_metadata(db_session, file)
        pytest.fail("Expected IntegrityError was not raised")
    except IntegrityError:
        pass
    finally:
        db_session.rollback()

def test_file_size_constraint(db_session):
    """Test that file size cannot exceed 100MB."""
    logger.info("Testing file size constraint")
    user = create_user(db_session)
    file = create_file(db_session, user)
    
    try:
        create_metadata(db_session, file, size=104857601)  # 100MB + 1 byte
        pytest.fail("Expected DataError was not raised")
    except DataError as e:
        logger.debug(f"Caught expected DataError for oversized file: {str(e)}")
        pass
    finally:
        db_session.rollback()
        logger.debug("Rolled back transaction")

def test_permission_with_nonexistent_file_fails(db_session):
    """Test that creating a permission for a non-existent file fails."""
    user = create_user(db_session)
    
    # Generate random bytes for ephemeral key and encode as base64
    ephemeral_bytes = uuid.uuid4().bytes + uuid.uuid4().bytes
    ephemeral_key = base64.b64encode(ephemeral_bytes).decode()
    
    try:
        permission = FilePermissions(
            file_id=99999,  # Non-existent file ID
            user_id=user.id,
            encryption_key=base64.b64encode(b"key").decode(),
            ephemeral_key=ephemeral_key,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC)
        )
        db_session.add(permission)
        db_session.commit()
        pytest.fail("Expected IntegrityError was not raised")
    except IntegrityError:
        pass
    finally:
        db_session.rollback()

def test_permission_with_nonexistent_user_fails(db_session):
    """Test that creating a permission for a non-existent user fails."""
    user = create_user(db_session)
    file = create_file(db_session, user)
    
    # Generate random bytes for ephemeral key and encode as base64
    ephemeral_bytes = uuid.uuid4().bytes + uuid.uuid4().bytes
    ephemeral_key = base64.b64encode(ephemeral_bytes).decode()
    
    try:
        permission = FilePermissions(
            file_id=file.id,
            user_id=99999,  # Non-existent user ID
            encryption_key=base64.b64encode(b"key").decode(),
            ephemeral_key=ephemeral_key,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC)
        )
        db_session.add(permission)
        db_session.commit()
        pytest.fail("Expected IntegrityError was not raised")
    except IntegrityError:
        pass
    finally:
        db_session.rollback()