from flask import Blueprint

auth_bp = Blueprint("authentication", __name__)

from app.authentication import routes