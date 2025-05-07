from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_oauthlib.client import OAuth
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-here')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
oauth = OAuth(app)

# Azure Key Vault setup
credential = DefaultAzureCredential()
key_vault_url = os.getenv('AZURE_KEY_VAULT_URL')
secret_client = SecretClient(vault_url=key_vault_url, credential=credential)

# Import routes after app initialization to avoid circular imports
from routes import auth, credentials, admin

# Register blueprints
app.register_blueprint(auth.bp)
app.register_blueprint(credentials.bp)
app.register_blueprint(admin.bp)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000) 