"""Database initialization script."""
import os
import pymysql
from config import config
from models.tables import Base
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

def init_local_db():
    """Initialize local MySQL database for development."""
    try:
        # Create connection to MySQL server without database
        connection = pymysql.connect(
            host=config.database.db_host,
            port=config.database.db_port,
            user=config.database.db_user,
            password=config.database.db_password
        )
        
        with connection.cursor() as cursor:
            # Create database if it doesn't exist
            cursor.execute(f"CREATE DATABASE IF NOT EXISTS {config.database.db_name}")
            print(f"Database '{config.database.db_name}' created or already exists")
            
        connection.close()
            
        # Create SQLAlchemy engine and create all tables
        engine = create_engine(
            f"mysql+pymysql://{config.database.db_user}:{config.database.db_password}@"
            f"{config.database.db_host}:{config.database.db_port}/{config.database.db_name}"
        )
        Base.metadata.create_all(engine)
        print("All tables created successfully")
            
    except Exception as e:
        print(f"Error while connecting to MySQL: {e}")

if __name__ == "__main__":
    if config.database.environment == "development":
        init_local_db()
    else:
        print("Skipping local database initialization in production mode") 