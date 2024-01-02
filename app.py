from flask import Flask, render_template
from markupsafe import escape
from flask_wtf import CSRFProtect

from forms import login, registration


import secrets

app = Flask(__name__)
app.secret_key = 'tO$&!|0wkamvVia0?n$NqIRVWOG'


foo = secrets.token_urlsafe(16)
app.secret_key = foo

csrf = CSRFProtect(app)


@app.route("/")
def index():
    return render_template('index.html')


@app.route("/<name>")
def hello(name):
    return f"Hello, {escape(name)}!"


@app.get("/profile")
def profile_get():
    return render_template('auth/profile.html')


@app.post("/profile")
def profile_post():
    return "Profile Page"


@app.get("/register")
def register_get():
    registration_form = registration.RegistrationForm() 
    return render_template('auth/register.html', form=registration_form)


@app.post("/register")
def register_post():
    return "Registration Page"


@app.get("/login")
def login_get():
    login_form = login.LoginForm() 
    return render_template('auth/login.html', form=login_form)


@app.post("/login")
def login_post():
    return "Login Page"
