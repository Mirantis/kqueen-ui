from kqueen_ui.api import get_service_client
from kqueen_ui.utils.fields import (
    EmailField,
    PasswordField,
    SelectField,
    StringField,
    TextAreaField,
)
from kqueen_ui.utils.forms import FlaskExtendableForm
from wtforms.validators import DataRequired, Email, EqualTo, Length

import yaml


class LoginForm(FlaskExtendableForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])


class ChangePasswordForm(FlaskExtendableForm):
    password_1 = PasswordField(
        'New Password',
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


class UserInviteForm(FlaskExtendableForm):
    email = EmailField('Email', validators=[Email()])

    def validate(self):
        if not FlaskExtendableForm.validate(self):
            return False

        # TODO: remove these uniqueness checks after introduction of unique constraint
        # in ETCD storage class on backend
        client = get_service_client()
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

        return True


class PasswordResetForm(FlaskExtendableForm):
    password_1 = PasswordField(
        'New Password',
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


class RequestPasswordResetForm(FlaskExtendableForm):
    email = EmailField('Email', validators=[Email()])

    def validate(self):
        if not FlaskExtendableForm.validate(self):
            return False

        # TODO: remove these uniqueness checks after introduction of unique constraint
        # in ETCD storage class on backend
        client = get_service_client()
        # Check if e-mail exists on backend
        response = client.user.list()
        if response.status > 200:
            self.email.errors.append('Can not contact backend at this time.')
            return False
        users = response.data
        user_emails = [u['email'] for u in users if 'email' in u]
        if self.email.data not in user_emails:
            self.email.errors.append('This e-mail is not registered.')
            return False

        return True


class ProvisionerCreateForm(FlaskExtendableForm):
    name = StringField('Name', validators=[DataRequired()])
    engine = SelectField('Engine', choices=[], switch=True)


class ClusterCreateForm(FlaskExtendableForm):
    name = StringField('Name', validators=[DataRequired()])
    provisioner = SelectField('Provisioner', validators=[DataRequired()], choices=[], switch=True)


class ClusterApplyForm(FlaskExtendableForm):
    apply = TextAreaField('Apply Resource', validators=[DataRequired()])


class ClusterHelmCreateForm(FlaskExtendableForm):
    name = StringField('Name', render_kw={'placeholder': 'Will be generated if left empty'})
    overrides = TextAreaField('Value Overrides')

    def validate(self):
        if not FlaskExtendableForm.validate(self):
            return False

        error = 'Value Overrides must be valid YAML key/value pairs.'
        if self.overrides.data:
            try:
                overrides = yaml.load(self.overrides.data)
                if not isinstance(overrides, dict):
                    self.overrides.errors.append(error)
                    return False
            except Exception:
                self.overrides.errors.append(error)
                return False
        return True
