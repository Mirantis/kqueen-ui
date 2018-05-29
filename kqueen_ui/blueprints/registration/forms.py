from flask_wtf import FlaskForm
from wtforms import PasswordField, StringField
from wtforms.fields.html5 import EmailField
from wtforms.validators import DataRequired, EqualTo, Length


class UserRegistrationForm(FlaskForm):
    organization_name = StringField('Organization Name', validators=[DataRequired()])
    email = EmailField('Email')
    password_1 = PasswordField(
        'Password',
        validators=[
            DataRequired(),
            Length(min=6, message='Password must be at least 6 characters long.')
        ]
    )
    password_2 = PasswordField(
        'Repeat Password',
        validators=[
            DataRequired(),
            EqualTo('password_1', message='Passwords does not match.')
        ]
    )

    def validate(self):
        if not FlaskForm.validate(self):
            return False

        # Cannot allow this Organization name, because it would cause issues on backend
        if self.organization_name.data == 'global':
            self.organization_name.errors.append('Cannot allow this Organization name for secret reasons, shush.')
            return False

        return True
