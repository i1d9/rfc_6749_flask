from flask import Flask
from config import Config


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Register blueprints
    from app.authentication import auth_bp
    app.register_blueprint(auth_bp)
    

    @app.route('/test')
    def test_page():
        return "<h1>Testing the flask application factory pattern</h1>"
    
    
    return app