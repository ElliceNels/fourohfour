import logging
from flask import Flask
from flask_cors import CORS
from dotenv import load_dotenv
import os
from src.server.routes.authentication_routes import authentication_routes as auth_bp
from src.server.routes.permission_routes import permission_bp
from src.server.routes.file_routes import files_bp
from src.server.utils.db_setup import setup_db

from src.server.logger import setup_logger

logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()
# Initialize the logger
setup_logger()

def create_app():
    app = Flask(__name__)
    logger.info('Flask app initialized')
    
    # Enable CORS
    CORS(app)
    logger.info('CORS enabled for Flask app')

    # DB configuration
    setup_db()

    # Basic configuration
    secret_key = os.getenv('SECRET_KEY')
    jwt_secret_key = os.getenv('JWT_SECRET_KEY')
    
    if secret_key is None:
        logger.warning("SECRET_KEY not set in environment, using default value: 'dev'")
        secret_key = 'dev'
    if jwt_secret_key is None:
        logger.warning("JWT_SECRET_KEY not set in environment, using default value: 'dev-jwt-secret'")
        jwt_secret_key = 'dev-jwt-secret'
    
    app.config['SECRET_KEY'] = secret_key
    app.config['JWT_SECRET_KEY'] = jwt_secret_key
    
    app.register_blueprint(auth_bp)
    app.register_blueprint(permission_bp)
    app.register_blueprint(files_bp)

    logger.info('Blueprints registered')

    @app.route('/')
    def index():
        return "<h1>Welcome to the best file sharing platform ever</h1>"
    
    return app

# Create the app instance
app = create_app()

if __name__ == '__main__':
    app.run(debug=True) 