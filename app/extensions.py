from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect
from flask_login import LoginManager


db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()
