from flask import Flask, render_template, redirect, url_for, flash
from markupsafe import escape
from flask_wtf import CSRFProtect

from forms import login, registration
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required


import os
import secrets
import bcrypt

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
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(80), nullable=False)
    last_name = db.Column(db.String(80), nullable=False)
    email_address = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    is_authenticated = db.Column(db.Boolean, unique=False, default=False)
    is_active = db.Column(db.Boolean, unique=False, default=False)
    is_anonymous = db.Column(db.Boolean, unique=False, default=True)

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

# TODO Arrange the app


class OauthCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(80), nullable=False)
    code = db.Column(db.String(80), nullable=False)
    client_id = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

    def __repr__(self):
        return '<OauthCode %r>' % self.first_name


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


@app.route("/")
def index():
    return render_template('index.html')


@app.route("/<name>")
def hello(name):
    return f"Hello, {escape(name)}!"


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    return render_template('auth/profile.html')


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
        print(user)

        if user and user.verify_password(login_form.password.data):

            print(user.id)
            login_user(user)
            flash('Logged in successfully.')
            return redirect(url_for('profile'))

    return render_template('auth/login.html', form=login_form)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))
