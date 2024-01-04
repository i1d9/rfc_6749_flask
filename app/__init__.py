from flask import Flask
from config import Config
from app.extensions import db
from app.models.user import User
from flask_wtf import CSRFProtect
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
import secrets

login_manager = LoginManager()
csrf = CSRFProtect()

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    foo = secrets.token_urlsafe(16)
    app.secret_key = foo

    csrf.init_app(app)  
    db.init_app(app)


    login_manager.init_app(app)
    login_manager.session_protection = "strong"
    login_manager.login_view = "auth.sign_in"



    # Register blueprints
    from app.authentication import auth_bp
    app.register_blueprint(auth_bp, url_prefix="/auth")

    from app.oauth import oauth_bp
    app.register_blueprint(oauth_bp, url_prefix="/oauth")
    

    @login_manager.user_loader
    def load_user(user_id):
        user = User.query.get(
            user_id)

        if user:
            return user
        else:
            return None

    @app.route('/test')
    def test_page():
        return "<h1>Testing the flask application factory pattern</h1>"
    
    
    return app