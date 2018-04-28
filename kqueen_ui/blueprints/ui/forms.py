from datetime import datetime
from kqueen_ui.utils.fields import (
    EmailField,
    PasswordField,
    SelectField,
    StringField,
    TextAreaField,
)
from kqueen_ui.utils.forms import FlaskExtendableForm
from pytz import common_timezones, timezone
from wtforms.validators import DataRequired, EqualTo, Length


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
    timezone = SelectField('Timezone', validators=[DataRequired()], choices=get_datetime_choices())


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
    auth_method = SelectField('Authentication Method', choices=[], switch=True)


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
    email = EmailField('Email')


class ProvisionerCreateForm(FlaskExtendableForm):
    name = StringField('Name', validators=[DataRequired()])
    engine = SelectField('Engine', choices=[], switch=True)


class ClusterCreateForm(FlaskExtendableForm):
    name = StringField('Name', validators=[DataRequired()])
    provisioner = SelectField('Provisioner', validators=[DataRequired()], choices=[], switch=True)


class ClusterApplyForm(FlaskExtendableForm):
    apply = TextAreaField('Apply Resource', validators=[DataRequired()])
