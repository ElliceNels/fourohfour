from flask import Flask
from flask_cors import CORS
from dotenv import load_dotenv
import os
from .routes import authenication_routes as auth_bp

# Load environment variables
load_dotenv()

def create_app():
    app = Flask(__name__)
    
    # Enable CORS
    CORS(app)
    
    # Basic configuration
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev')
    
    # Register blueprints
    app.register_blueprint(auth_bp)
    # app.register_blueprint(files_bp)
    
    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True) 