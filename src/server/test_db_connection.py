import pytest
import logging
from sqlalchemy import text
from src.server.config import config
from src.server.utils.db_setup import setup_db, get_session

logger = logging.getLogger(__name__)

def test_db_connection():
    """Test that we can connect to the database using the application's setup_db function."""
    try:
        # Use the application's database setup
        setup_db()
        
        # Get a session and verify we can connect
        with get_session() as session:
            # Verify we're connected to the correct database
            db_name = session.execute(text("SELECT DATABASE()")).scalar()
            assert db_name == config.database.db_name, f"Connected to wrong database: {db_name}"
            logger.info(f"Successfully connected to database: {db_name}")
        
    except Exception as e:
        pytest.fail(f"Failed to connect to database: {str(e)}") 