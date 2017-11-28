from flask_wtf import FlaskForm
from kqueen_ui.utils.fields import (
    EmailField,
    FileField,
    IntegerField,
    JsonFileField,
    PasswordField,
    StringField,
    TextAreaField,
    YamlFileField
)


class FlaskExtendableForm(FlaskForm):

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
            if field_params['type'] == 'email':
                field_class = EmailField
            elif field_params['type'] == 'file':
                field_class = FileField
            elif field_params['type'] == 'integer':
                field_class = IntegerField
            elif field_params['type'] == 'json_file':
                field_class = JsonFileField
            elif field_params['type'] == 'password':
                field_class = PasswordField
            elif field_params['type'] == 'text':
                field_class = StringField
            elif field_params['type'] == 'text_area':
                field_class = TextAreaField
            elif field_params['type'] == 'yaml_file':
                field_class = YamlFileField
            if field_class:
                label = field_params['label'] if 'label' in field_params else field_name
                jsvalidators = field_params['validators'] if 'validators' in field_params else {}
                field = field_class(label, switchtag=switchtag, jsvalidators=jsvalidators)
                setattr(cls, field_name, field)
