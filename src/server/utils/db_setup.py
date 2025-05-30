from server.config import config 
from server.models.tables import Base
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
import os
import logging
# Add sqlalchemy-utils for database existence check and creation
from sqlalchemy_utils import database_exists, create_database

logger = logging.getLogger(__name__)

_Session = None

def get_session():
    """Get a new session for database operations."""
    global _Session
    if _Session is None:
        # Initialize the session only once (singleton pattern)
        setup_db()
    return _Session()

def setup_db(name: str = None):
    """Setup the database connection and create tables."""
    # Get database credentials from environment variables
    DB_USER = os.getenv('DB_USER')
    DB_PASSWORD = os.getenv('DB_PASSWORD')
    # Log if sensitive credentials are not set
    if DB_USER is None:
        logger.warning("DB_USER not set in environment, using default value: 'db_user'")
        DB_USER = 'db_user'
    if DB_PASSWORD is None:
        logger.warning("DB_PASSWORD not set in environment, using default value: 'db_password'")
        DB_PASSWORD = 'db_password'
    if not name:
        name = config.database.db_name

    db_engine = f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{config.database.db_host}:{config.database.db_port}/{name}"    
    
    try:
        engine = create_engine(db_engine)

        # Ensure the database exists (will create if not)
        if not database_exists(engine.url):
            logger.info(f"Database {config.database.db_name} does not exist. Creating it...")
            create_database(engine.url)
            logger.info(f"Database {config.database.db_name} created.")
    except Exception as e:
        logger.error(f"Failed to create database {config.database.db_name}: {e}")
        raise

    Base.metadata.create_all(engine)
    logger.info(f"Database {config.database.db_name} at {config.database.db_host}:{config.database.db_port} connected.")

    global _Session
    _Session = sessionmaker(bind=engine)
    return engine