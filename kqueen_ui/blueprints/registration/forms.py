from flask_wtf import FlaskForm
from kqueen_ui.api import get_service_client
from slugify import slugify
from wtforms import PasswordField, StringField
from wtforms.fields.html5 import EmailField
from wtforms.validators import DataRequired, Email, EqualTo, Length


class UserRegistrationForm(FlaskForm):
    organization_name = StringField('Organization Name', validators=[DataRequired()])
    email = EmailField('Email', validators=[Email()])
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

        # TODO: remove these uniqueness checks after introduction of unique constraint
        # in ETCD storage class on backend
        client = get_service_client()
        # Check if organization exists on backend
        response = client.organization.list()
        if response.status > 200:
            self.organization_name.errors.append('Can not contact backend at this time.')
            return False
        organizations = response.data
        organization_names = [org['name'] for org in organizations]
        organization_namespaces = [o['namespace'] for o in organizations]
        if self.organization_name.data in organization_names or slugify(self.organization_name.data) in organization_namespaces:
            self.organization_name.errors.append('Organization {} already exists.'.format(self.organization_name.data))
            return False

        # Check if e-mail and username exists on backend
        response = client.user.list()
        if response.status > 200:
            self.email.errors.append('Can not contact backend at this time.')
            return False
        users = response.data
        user_emails = [u['email'] for u in users if 'email' in u]
        if self.email.data in user_emails:
            self.email.errors.append('This e-mail is already registered.')
            return False
        user_usernames = [u['username'] for u in users]
        if self.email.data in user_usernames:
            self.email.errors.append('This username is already registered.')
            return False

        return True
