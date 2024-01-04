from app.authentication import auth_bp

from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from app.forms import login, registration
from flask import render_template, redirect, url_for, flash, request, jsonify

from app.models.user import User
from app.extensions import db
from app.oauth.verify import verify_access_token


@auth_bp.route("/register", methods=["GET", "POST"])
def sign_up():
    registration_form = registration.RegistrationForm()
    if registration_form.validate_on_submit() and User.query.filter_by(
            email_address=registration_form.email_address.data).first() is None:
        user = User(first_name=registration_form.first_name.data, last_name=registration_form.first_name.data,
                    email_address=registration_form.first_name.data, password=registration_form.password.data)

        user.hash_password()
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('authentication.sign_in'))

    return render_template('auth/register.html', form=registration_form)


@auth_bp.route("/login", methods=["GET", "POST"])
def sign_in():
    login_form = login.LoginForm()
    if login_form.validate_on_submit():
        user = User.query.filter_by(
            email_address=login_form.email_address.data).first()

        if user and user.verify_password(login_form.password.data):
            login_user(user)
            flash('Logged in successfully.')
            next = request.args.get('next')
            return redirect(next or redirect(url_for('authentication.profile')))

    return render_template('auth/login.html', form=login_form)


@auth_bp.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    return render_template('auth/profile.html')


@auth_bp.route("/user/info")
@verify_access_token
def user_info(current_user):
    return jsonify({
        "first_name": current_user.first_name,
        "email_address": current_user.email_address,
        "last_name": current_user.last_name,
    })

@auth_bp.route("/logout")
@login_required
def sign_out():
    logout_user()
    return redirect(url_for('index'))
