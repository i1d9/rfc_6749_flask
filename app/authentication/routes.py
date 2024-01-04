from app.authentication import auth_bp

from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from forms import login, registration


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
        return redirect(url_for('login_request'))

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
            return redirect(url_for('profile'))

    return render_template('auth/login.html', form=login_form)


@auth_bp.route("/logout")
@login_required
def sign_out():
    logout_user()
    return redirect(url_for('index'))
