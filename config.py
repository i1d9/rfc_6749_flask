import os
import secrets

basedir = os.path.abspath(os.path.dirname(__file__))


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_urlsafe(16)
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URI')\
        or 'sqlite:///' + os.path.join(basedir, 'app.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    DEBUG = os.environ.get('DEBUG') or True
    ENV = os.environ.get('ENV') or "development"
    FLASK_DEBUG = os.environ.get('DEBUG') or True
    FLASK_APP = os.environ.get('DEBUG') or "app"
    FLASK_ENV = os.environ.get('ENV') or "development"