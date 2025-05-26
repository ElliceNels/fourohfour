from src.server.config import config 
from src.server.models.tables import Base
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
import os
import logging

logger = logging.getLogger(__name__)

_Session = None

def get_session():
    """Get a new session for database operations."""
    global _Session
    if _Session is None:
        # Initialize the session only once (singleton pattern)
        setup_db()
    return _Session()

def setup_db():
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

    db_engine = f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{config.database.db_host}:{config.database.db_port}/{config.database.db_name}"    
    engine = create_engine(db_engine)
    Base.metadata.create_all(engine)

    global _Session
    _Session = sessionmaker(bind=engine)