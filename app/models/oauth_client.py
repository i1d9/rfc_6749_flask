from app.extensions import db
from datetime import datetime

class OauthClient(db.Model):

    __tablename__ = 'oauth_clients'

    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.String(80), unique=True, nullable=False)
    name = db.Column(db.String(255), unique=True, nullable=False)
    client_secret = db.Column(db.String(80), nullable=False)
    endpoint = db.Column(db.String(255), unique=True, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
