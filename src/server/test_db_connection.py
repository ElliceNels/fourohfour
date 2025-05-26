import pymysql
import os
import logging
from config import config

logger = logging.getLogger(__name__)

def test_connection():
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

        # Attempt to connect to the database
        logger.info("Attempting to connect to the database...")
        cnx = pymysql.connect(
            user=db_user,
            password=db_password,
            host=db_host,
            port=db_port,
            database=db_name
        )
        
        with cnx.cursor() as cursor:
            cursor.execute("SELECT VERSION()")
            version = cursor.fetchone()
            logger.info(f"Connected to MySQL Server version {version[0]}")
            
            cursor.execute("SELECT DATABASE()")
            db = cursor.fetchone()
            logger.info(f"Connected to database: {db[0]}")
            
        cnx.close()
        logger.info("MySQL connection is closed")
            
    except Exception as e:
        logger.error(f"Error while connecting to MySQL: {e}")

if __name__ == "__main__":
    test_connection() 