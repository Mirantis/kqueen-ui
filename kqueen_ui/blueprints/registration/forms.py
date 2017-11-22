from flask_wtf import FlaskForm
from kqueen_ui.api import get_service_client
from wtforms import PasswordField, StringField
from wtforms.fields.html5 import EmailField
from wtforms.validators import DataRequired, Email


class UserRegistrationForm(FlaskForm):
    organization_name = StringField('Organization Name', validators=[DataRequired()])
    username = StringField('Username', validators=[DataRequired()])
    email = EmailField('Email', validators=[Email()])
    password_1 = PasswordField('Password', validators=[DataRequired()])
    password_2 = PasswordField('Repeat Password', validators=[DataRequired()])

    def validate(self):
        if not FlaskForm.validate(self):
            return False
        if not self.password_1.data == self.password_2.data:
            self.password_2.errors.append('Passwords does not match.')
            return False

        # Check if organization exists on backend
        client = get_service_client()
        response = client.organization.list()
        if response.status > 200:
            self.organization_name.errors.append('Can not contact backend at this time.')
            return False
        organizations = response.data
        organization_names = [o['name'] for o in organizations]
        if self.organization_name.data in organization_names:
            self.organization_name.errors.append('Organization {} already exists.'.format(self.organization_name.data))
            return False

        return True
