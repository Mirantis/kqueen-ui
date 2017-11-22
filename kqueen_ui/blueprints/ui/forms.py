from flask_wtf import FlaskForm as WTFlaskForm
from flask_wtf.file import FileField
from wtforms import PasswordField as WTPasswordField, SelectField as WTSelectField, StringField as WTStringField, TextAreaField as WTTextAreaField
from wtforms.fields.html5 import EmailField
from wtforms.validators import DataRequired, Email, EqualTo


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


class UserCreateForm(FlaskForm):
    email = EmailField('Email', validators=[Email()])


class ProvisionerCreateForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    engine = SelectField('Engine', choices=[], switch=True)


class ClusterCreateForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    kubeconfig = FileField()
    provisioner = SelectField('Provisioner', validators=[DataRequired()], choices=[])


class ClusterApplyForm(FlaskForm):
    apply = TextAreaField('Apply Resource', validators=[DataRequired()])
