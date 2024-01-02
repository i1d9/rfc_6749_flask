from flask_wtf import FlaskForm
from wtforms import StringField,URLField, SubmitField
from wtforms.validators import DataRequired, Email


class LoginForm(FlaskForm):
	name = StringField("Name", validators=[DataRequired()])
    redirect_uri = URLField("Redirect URI", validators=[DataRequired()])
    submit = SubmitField('Submit')
