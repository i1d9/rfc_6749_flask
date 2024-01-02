from flask import Flask
from markupsafe import escape
from flask_wtf import  CSRFProtect
import secrets

app = Flask(__name__)
app.secret_key = 'tO$&!|0wkamvVia0?n$NqIRVWOG'



foo = secrets.token_urlsafe(16)
app.secret_key = foo

csrf = CSRFProtect(app)


@app.route("/")
def index():
    return "<p>Hello, World!</p>"


@app.route("/<name>")
def hello(name):
    return f"Hello, {escape(name)}!"


@app.get("/profile")
def profile_get():
    return "Profile Page"


@app.post("/profile")
def profile_post():
    return "Profile Page"

@app.get("/register")
def register_get():
    return "Registration Page"


@app.post("/register")
def register_post():
    return "Registration Page"


@app.get("/login")
def login_get():
    return "Login Page"


@app.post("/login")
def login_post():
    return "Login Page"
