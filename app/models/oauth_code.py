from app.extensions import db
from datetime import datetime



class OauthCode(db.Model):

    __tablename__ = 'oauth_codes'

    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(80), nullable=False)
    code = db.Column(db.String(255), nullable=False)
    client_code = db.Column(db.String(255), unique=True, nullable=True)
    client_id = db.Column(db.Integer, db.ForeignKey('oauth_clients.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    expiry_time = db.Column(db.DateTime(timezone=True),
                            default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return '<OauthCode %r>' % self.code
