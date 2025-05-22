from flask import Flask
from flask_cors import CORS
from dotenv import load_dotenv
import os
from routes.authentication_routes import authentication_routes as auth_bp
from routes.permission_routes import permission_bp
from routes.file_routes import files_bp
from config import config 
from models.tables import Base
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine

# Load environment variables
load_dotenv()

def create_app():
    app = Flask(__name__)
    
    # Enable CORS
    CORS(app)

    # DB configuration
    DB_USER = os.getenv('DB_USER')
    DB_PASSWORD = os.getenv('DB_PASSWORD')
    
    # TEMPORARLY COMMENTED OUT TO AVOID DB CONNECTION ERROR
    # db_engine = f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{config.database.db_host}:{config.database.db_port}/{config.database.db_name}"    
    # engine = create_engine(db_engine)
    # Base.metadata.create_all(engine)
    # Session = sessionmaker(bind=engine)
    
    # Basic configuration
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev')
    
    app.register_blueprint(auth_bp)
    app.register_blueprint(permission_bp)
    app.register_blueprint(files_bp)

    @app.route('/')
    def index():
        return "<h1>Welcome to the best file sharing platform ever</h1>"
    
    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True) 