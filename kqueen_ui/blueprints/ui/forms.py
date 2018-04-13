from datetime import datetime
from kqueen_ui.api import get_service_client
from kqueen_ui.utils.fields import (
    EmailField,
    PasswordField,
    SelectField,
    StringField,
    TextAreaField,
)
from kqueen_ui.utils.forms import FlaskExtendableForm
from pytz import common_timezones, timezone
from wtforms.validators import DataRequired, Email, EqualTo, Length


def get_datetime_choices():
    now = datetime.utcnow()
    tmpl = '(GMT{offset}) {name}'
    choices = []
    for tz_name in common_timezones:
        tz = timezone(tz_name)
        localized = tz.localize(now)
        fmt = {
            'offset': localized.strftime('%z'),
            'name': tz_name.split('/')[-1].replace('_', ' ')
        }
        choice = (tz_name, tmpl.format(**fmt))
        choices.append(choice)
    choices.sort(key=lambda k: k[1])
    return choices


class LoginForm(FlaskExtendableForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])


class UserProfileForm(FlaskExtendableForm):
    timezone = SelectField('Timezone', validators=[DataRequired()],
                           choices=get_datetime_choices())


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

        # TODO: remove these uniqueness checks after introduction of unique
        # constraint in ETCD storage class on backend
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

        # TODO: remove these uniqueness checks after introduction of unique
        # constraint in ETCD storage class on backend
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
    provisioner = SelectField('Provisioner', validators=[DataRequired()],
                              choices=[], switch=True)


class ClusterApplyForm(FlaskExtendableForm):
    apply = TextAreaField('Apply Resource', validators=[DataRequired()])
