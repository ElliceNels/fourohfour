import logging
from flask import Flask
from flask_cors import CORS
from dotenv import load_dotenv
# Load environment variables
load_dotenv()
import os
from server.routes.authentication_routes import authentication_routes as auth_bp
from server.routes.permission_routes import permission_bp
from server.routes.file_routes import files_bp
from server.utils.db_setup import setup_db
from server.utils.security import apply_security_headers
from server.logger import setup_logger

logger = logging.getLogger(__name__)
EXIT_ERROR = 1

# Initialize the logger
setup_logger()

def create_app():
    app = Flask(__name__)
    logger.info('Flask app initialized')
    
    # Enable CORS
    CORS(app)
    logger.info('CORS enabled for Flask app')

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

    @app.after_request
    def add_security_headers(response):
        return apply_security_headers(response)

    @app.route('/')
    def index():
        return "<h1>Welcome to the best file sharing platform ever</h1>"
    
    return app

app = create_app()

if __name__ == '__main__':
    try:
        setup_db()
    except Exception as e:
        logger.critical(f"Failed to setup database: {e}")
        exit(EXIT_ERROR)

    app.run(debug=True) 
