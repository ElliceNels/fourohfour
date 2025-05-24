from ..config import config 
from ..models.tables import Base
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
import os

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
    DB_USER = os.getenv('DB_USER')
    DB_PASSWORD = os.getenv('DB_PASSWORD')

    db_engine = f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{config.database.db_host}:{config.database.db_port}/{config.database.db_name}"    
    engine = create_engine(db_engine)
    Base.metadata.create_all(engine)

    global _Session
    _Session = sessionmaker(bind=engine)


from sqlalchemy import create_engine
from .models.tables import Base
from .config import config

def setup_database():
    # Create database engine
    engine = create_engine(
        f"mysql+pymysql://{config.database.db_user}:{config.database.db_password}@"
        f"{config.database.db_host}:{config.database.db_port}/{config.database.db_name}"
    )
    
    # Create all tables
    Base.metadata.create_all(engine)
    print("Database tables created successfully!")

if __name__ == "__main__":
    setup_database() 