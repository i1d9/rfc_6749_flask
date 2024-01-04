from flask import Flask
from config import Config
from app.extensions import db, login_manager, csrf
from app.models.user import User
from app.models.oauth_client import OauthClient


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)


    csrf.init_app(app)
    db.init_app(app)


    login_manager.init_app(app)
    login_manager.session_protection = "strong"
    login_manager.login_view = "authentication.sign_in"

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

    with app.app_context():
        db.create_all()
        default_client = OauthClient.query.filter_by(name='default').first()

        if default_client is None:
            client = OauthClient(
                name="default", client_secret="client_secret", client_id="client_id", endpoint="https://oauth.pstmn.io/v1/callback")
            db.session.add(client)
            db.session.commit()

    return app
