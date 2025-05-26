"""Database initialization script."""
import os
import pymysql
import logging
from config import config
from models.tables import Base
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

logger = logging.getLogger(__name__)

def init_local_db():
    """Initialize local MySQL database for development."""
    try:
        # Get database credentials from environment variables
        db_user = os.getenv('DB_USER')
        db_password = os.getenv('DB_PASSWORD')
        
        # Log if sensitive credentials are not set
        if db_user is None:
            logger.warning("DB_USER not set in environment, using default value: 'fourohfour'")
            db_user = 'fourohfour'
        if db_password is None:
            logger.warning("DB_PASSWORD not set in environment, using default value: 'fourohfour'")
            db_password = 'fourohfour'

        # Use config values for non-sensitive database settings
        db_host = config.database.db_host
        db_port = config.database.db_port
        db_name = config.database.db_name

        # Create connection to MySQL server without database
        connection = pymysql.connect(
            host=config.database.db_host,
            port=config.database.db_port,
            user=db_user,
            password=db_password
        )
        
        with connection.cursor() as cursor:
            # Create database if it doesn't exist
            cursor.execute(f"CREATE DATABASE IF NOT EXISTS {db_name}")
            logger.info(f"Database '{db_name}' created or already exists")
            
        connection.close()
            
        # Create SQLAlchemy engine and create all tables
        engine = create_engine(
            f"mysql+pymysql://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}"
        )
        Base.metadata.create_all(engine)
        logger.info("All tables created successfully")
            
    except Exception as e:
        logger.error(f"Error while connecting to MySQL: {e}")

if __name__ == "__main__":
    if config.database.environment == "development":
        init_local_db()
    else:
        logger.info("Skipping local database initialization in production mode") 