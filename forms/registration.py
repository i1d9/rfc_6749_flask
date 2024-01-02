from flask_wtf import FlaskForm
from wtforms import StringField,PasswordField, SubmitField
from wtforms.validators import DataRequired, Email


class RegistrationForm(FlaskForm):
	first_name = StringField("First Name", validators=[DataRequired()])
	last_name = StringField("Last Name", validators=[DataRequired()])
	email_address = StringField("Email Address", validators=[DataRequired(), Email()])
	password = PasswordField("Password", validators=[DataRequired()])
	submit = SubmitField("Submit")


