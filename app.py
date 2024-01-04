from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from markupsafe import escape
from flask_wtf import CSRFProtect

from forms import login, registration
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from urllib.parse import urlencode

from datetime import datetime, timedelta
from functools import wraps

import os
import secrets
import bcrypt
import base64
import hashlib
import jwt

basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.secret_key = 'tO$&!|0wkamvVia0?n$NqIRVWOG'


foo = secrets.token_urlsafe(16)
app.secret_key = foo
app.config['SQLALCHEMY_DATABASE_URI'] =\
    'sqlite:///' + os.path.join(basedir, 'database.db')

db = SQLAlchemy(app)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.session_protection = "strong"
login_manager.login_view = "login"


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(80), nullable=False)
    last_name = db.Column(db.String(80), nullable=False)
    email_address = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    is_authenticated = db.Column(db.Boolean, unique=False, default=False)
    is_active = db.Column(db.Boolean, unique=False, default=False)
    is_anonymous = db.Column(db.Boolean, unique=False, default=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def hash_password(self):
        # Hash a password for the first time
        #   (Using bcrypt, the salt is saved into the hash itself)
        self.password = bcrypt.hashpw(self.password, bcrypt.gensalt())
        return self.password

    def verify_password(self, plain_text_password):
        # Check hashed password. Using bcrypt, the salt is saved into the hash itself
        return bcrypt.checkpw(plain_text_password, self.password)

    def is_active(self):
        """True, as all users are active."""
        return True

    def get_id(self):
        """Return the email address to satisfy Flask-Login's requirements."""
        return self.id

    def is_authenticated(self):
        """Return True if the user is authenticated."""
        return self.authenticated

    def is_anonymous(self):
        """False, as anonymous users aren't supported."""
        return False

    def __repr__(self):
        return '<User %r>' % self.email_address


class OauthClient(db.Model):

    __tablename__ = 'oauth_clients'

    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.String(80), unique=True, nullable=False)
    name = db.Column(db.String(255), unique=True, nullable=False)
    client_secret = db.Column(db.String(80), nullable=False)
    endpoint = db.Column(db.String(255), unique=True, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# TODO Arrange the app
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


# Form Protection - https://en.wikipedia.org/wiki/Cross-site_request_forgery
csrf = CSRFProtect(app)


@login_manager.user_loader
def load_user(user_id):
    user = User.query.get(
        user_id)

    if user:
        return user
    else:
        return None


@login_manager.unauthorized_handler
def unauthorized():
    return redirect(url_for('login_request'))


with app.app_context():
    db.create_all()
    default_client = OauthClient.query.filter_by(name='default').first()

    if default_client is None:
        client = OauthClient(
            name="default", client_secret="client_secret", client_id="client_id", endpoint="https://oauth.pstmn.io/v1/callback")
        db.session.add(client)
        db.session.commit()


def verify_access_token(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if "Authorization" in request.headers:
            token = request.headers["Authorization"].split(" ")[1]

        if not token:
            return {
                "error_description": "Access denied",
                "error": "Unauthorized"

            }, 401
        try:
            data = jwt.decode(token, 'secret', algorithms=['HS512'])

            current_user = User.query.get(data["user_id"])
            if current_user is None:
                return {
                    "error_description": "Invalid Access Token",
                    "error": "Unauthorized"

                }, 401
        except Exception as e:
            return {
                "error_description": str(e),
                "error": "internal server error"
            }, 500
        return f(current_user, *args, **kwargs)
    return decorated


@app.route("/")
def index():
    return render_template('index.html')


@app.route("/<name>")
def hello(name):
    return f"Hello, {escape(name)}!"


@app.route("/user/info")
@verify_access_token
def user_info(current_user):
    return jsonify({
        "first_name": current_user.first_name,
        "email_address": current_user.email_address,
        "last_name": current_user.last_name,
    })


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    return render_template('auth/profile.html')


@app.route("/oauth/authorization", methods=["GET", "POST"])
@login_required
def authorization():
    args = request.args
    client_id = args.get('client_id')
    redirect_uri = args.get('redirect_uri')
    response_type = args.get('response_type')
    code_challenge = args.get('code_challenge')
    code_challenge_method = args.get('code_challenge_method')

    if None not in [client_id, redirect_uri, response_type, code_challenge, code_challenge_method] and code_challenge_method == "S512":
        # Try resolving the client from the database
        client = OauthClient.query.filter_by(
            client_id=client_id, endpoint=redirect_uri).first()

        if client:
            # When a client is found, the request method is POST and the resource owner has accepted the request
            if request.method == "POST" and request.form["accept"] == "1":

                current_time = datetime.now()
                minutes_later = timedelta(minutes=5)
                code = secrets.token_urlsafe(24)
                oauth_code = OauthCode(
                    type=response_type,
                    client_code=code_challenge,
                    client_id=client.id, user_id=current_user.id, expiry_time=current_time + minutes_later, code=code)

                db.session.add(oauth_code)
                db.session.commit()

                parameters = dict(code=oauth_code.code)
                redirect_url = redirect_uri + \
                    ("?" + urlencode(parameters) if parameters else "")

                return redirect(redirect_url)
            # When a client is found, the request method is POST and the resource owner has revoked the request
            elif request.method == "POST" and request.form["accept"] == "0":

                parameters = dict(
                    error="access_denied", error_description="resource owner revoked request")
                redirect_url = redirect_uri + \
                    ("?" + urlencode(parameters) if parameters else "")

                return redirect(redirect_url)
            # When a client is found, the request method is GET
            # This should be the default block that runs then the client is found
            else:

                return render_template('auth/consent.html', client=client)
        else:
            # When the provided params(redirect_uri and client_id) are not associated with a client
            parameters = dict(error="unauthorized_client",
                              error_description="invalid client id and redirect uri")
            redirect_url = redirect_uri + \
                ("?" + urlencode(parameters) if parameters else "")
            return redirect(redirect_url)

    elif redirect_uri is not None:
        # When the provided request params are invalid/dont contain all required params
        parameters = dict(error="invalid_request")
        redirect_url = redirect_uri + \
            ("?" + urlencode(parameters) if parameters else "")

        return redirect(redirect_url)

    # Ultimately redirect to the home page
    return redirect(url_for('index'))


@app.post("/oauth/token")
@csrf.exempt
def access_token_endpoint():
    args = request.json

    grant_type = args.get('grant_type')
    code = args.get('code')
    redirect_uri = args.get('redirect_uri')
    client_id = args.get('client_id')
    code_verifier = args.get('code_verifier')

    if None not in [client_id, redirect_uri, grant_type, code, code_verifier]:
        # Try resolving the client from the database
        client = OauthClient.query.filter_by(
            client_id=client_id, endpoint=redirect_uri).first()
        data = {}
        current_time = datetime.now()
        hour_later = timedelta(hours=1)
        if client:
            match grant_type:
                case "authorization_code":
                    if None not in [code_verifier, code]:

                        oauth_code = OauthCode.query.filter_by(
                            code=code,
                            client_id=client.id,  type="authorization_code").first()

                        hash = hashlib.sha512(
                            code_verifier.encode('UTF-8')).digest()

                        computed_challenge = base64.urlsafe_b64encode(
                            (hash)).decode("utf-8")

                        if oauth_code and oauth_code.client_code == computed_challenge and oauth_code.expiry_time > current_time:

                            encoded_jwt = jwt.encode(
                                {'user_id': str(oauth_code.user_id)}, 'secret', algorithm='HS512')

                            access_token = OauthCode(
                                type="access_token",
                                client_id=client.id, user_id=oauth_code.user_id, expiry_time=current_time + hour_later, code=encoded_jwt)

                            data = {
                                "access_token": access_token.code,
                                "token_type": "Bearer",
                                "expires_in": 3600,
                            }
                        else:

                            data = {"error": "invalid_request",
                                    "error_description": "invalid parameters provided",
                                    }
                    else:
                        data = {"error": "invalid_request",
                                "error_description": "invalid parameters provided",
                                }

                case "password":
                    data = {
                        "access_token": "2YotnFZFEjr1zCsicMWpAA",
                        "token_type": "Bearer",
                        "expires_in": 3600,
                    }
                case "client_credentials":
                    data = {
                        "access_token": "2YotnFZFEjr1zCsicMWpAA",
                        "token_type": "Bearer",
                        "expires_in": 3600,
                    }
                case _:
                    data = {
                        "access_token": "2YotnFZFEjr1zCsicMWpAA",
                        "token_type": "Bearer",
                        "expires_in": 3600,
                    }

        return jsonify(data)

    data = {"error": "invalid_request",
            "error_description": "invalid parameters provided",
            }

    return jsonify(data)


@app.route("/register", methods=["GET", "POST"])
def register():
    registration_form = registration.RegistrationForm()
    if registration_form.validate_on_submit() and User.query.filter_by(
            email_address=registration_form.email_address.data).first() is None:
        user = User(first_name=registration_form.first_name.data, last_name=registration_form.first_name.data,
                    email_address=registration_form.first_name.data, password=registration_form.password.data)

        user.hash_password()
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login_request'))

    return render_template('auth/register.html', form=registration_form)


@app.route("/login", methods=["GET", "POST"])
def login_request():
    login_form = login.LoginForm()
    if login_form.validate_on_submit():
        user = User.query.filter_by(
            email_address=login_form.email_address.data).first()

        if user and user.verify_password(login_form.password.data):
            login_user(user)
            flash('Logged in successfully.')
            return redirect(url_for('profile'))

    return render_template('auth/login.html', form=login_form)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))
