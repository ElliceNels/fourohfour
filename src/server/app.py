from flask import Flask
from flask_cors import CORS
from dotenv import load_dotenv
import os
from src.server.routes.authentication_routes import authentication_routes as auth_bp
from src.server.routes.permission_routes import permission_bp
from src.server.routes.file_routes import files_bp
from src.server.utils.db_setup import setup_db

# Load environment variables
load_dotenv()

def create_app():
    app = Flask(__name__)
    
    # Enable CORS
    CORS(app)

    # DB configuration
    # setup_db()

    # Basic configuration
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev')
    app.config['JWT_SECRET_KEY'] = JWT_SECRET_KEY
    
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