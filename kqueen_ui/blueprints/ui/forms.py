from flask_wtf import FlaskForm as WTFlaskForm
from flask_wtf.file import FileField as WTFileField
from kqueen_ui.api import get_service_client
from werkzeug.datastructures import FileStorage
from wtforms import (
    IntegerField as WTIntegerField,
    PasswordField as WTPasswordField,
    SelectField as WTSelectField,
    StringField as WTStringField,
    TextAreaField as WTTextAreaField
)
from wtforms.fields.html5 import EmailField
from wtforms.validators import DataRequired, Email, EqualTo

import json
import yaml


#
# EXTENSIONS
#

class SelectableMixin:
    switchtag = None
    jsvalidators = {}

    def __init__(self, *args, **kwargs):
        self.switchtag = kwargs.pop('switchtag', None)
        self.jsvalidators = kwargs.pop('jsvalidators', None)
        super(SelectableMixin, self).__init__(*args, **kwargs)


class IntegerField(SelectableMixin, WTIntegerField):
    pass


class FileField(SelectableMixin, WTFileField):
    pass


class JsonFileField(FileField):

    def process_formdata(self, valuelist):
        super(JsonFileField, self).process_formdata(valuelist)
        if self.data and isinstance(self.data, FileStorage):
            try:
                self.data = json.loads(self.data)
            except Exception as e:
                logger.error('Could not load JSON file: {}'.format(repr(e)))


class YamlFileField(FileField):

    def process_formdata(self, valuelist):
        super(YamlFileField, self).process_formdata(valuelist)
        if self.data and isinstance(self.data, FileStorage):
            try:
                self.data = yaml.load(self.data)
            except Exception as e:
                logger.error('Could not load YAML file: {}'.format(repr(e)))


class PasswordField(SelectableMixin, WTPasswordField):
    pass


class SelectField(SelectableMixin, WTSelectField):
    switch = False

    def __init__(self, *args, **kwargs):
        self.switch = kwargs.pop('switch', False)
        super(SelectField, self).__init__(*args, **kwargs)


class StringField(SelectableMixin, WTStringField):
    pass


class TextAreaField(SelectableMixin, WTTextAreaField):
    pass


class FlaskForm(WTFlaskForm):

    @classmethod
    def append_fields(cls, ctx, switchtag=None):
        '''
            {
                'username': {
                    'type': 'text',
                    'label': 'Username',
                    'validators': {
                        'required': True
                    }
                },
                'password': {
                    'type': 'password',
                    'label': 'Password',
                    'validators': {
                        'required': True
                    }
                }
            }
        '''
        for field_name, field_params in ctx.items():
            field_class = None
            if field_params['type'] == 'text':
                field_class = StringField
            elif field_params['type'] == 'password':
                field_class = PasswordField
            elif field_params['type'] == 'integer':
                field_class = IntegerField
            elif field_params['type'] == 'file':
                field_class = FileField
            elif field_params['type'] == 'json_file':
                field_class = JsonFileField
            elif field_params['type'] == 'yaml_file':
                field_class = YamlFileField
            if field_class:
                label = field_params['label'] if 'label' in field_params else field_name
                jsvalidators = field_params['validators'] if 'validators' in field_params else {}
                field = field_class(label, switchtag=switchtag, jsvalidators=jsvalidators)
                setattr(cls, field_name, field)


#
# FORMS
#

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])


class ChangePasswordForm(FlaskForm):
    password_1 = PasswordField('New Password', validators=[DataRequired()])
    password_2 = PasswordField(
        'Repeat Password',
        validators=[
            DataRequired(),
            EqualTo('password_1', message='Passwords does not match.')
        ]
    )


class UserInviteForm(FlaskForm):
    email = EmailField('Email', validators=[Email()])

    def validate(self):
        if not FlaskForm.validate(self):
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


class PasswordResetForm(FlaskForm):
    password_1 = PasswordField('New Password', validators=[DataRequired()])
    password_2 = PasswordField(
        'Repeat Password',
        validators=[
            DataRequired(),
            EqualTo('password_1', message='Passwords does not match.')
        ]
    )


class RequestPasswordResetForm(FlaskForm):
    email = EmailField('Email', validators=[Email()])

    def validate(self):
        if not FlaskForm.validate(self):
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


class ProvisionerCreateForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    engine = SelectField('Engine', choices=[], switch=True)


class ClusterCreateForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    provisioner = SelectField('Provisioner', validators=[DataRequired()], choices=[], switch=True)


class ClusterApplyForm(FlaskForm):
    apply = TextAreaField('Apply Resource', validators=[DataRequired()])
