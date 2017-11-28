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


TYPE_MAP = {
    'email': EmailField,
    'file': FileField,
    'integer': IntegerField,
    'json_file': JsonFileField,
    'password': PasswordField,
    'text': StringField,
    'text_area': TextAreaField,
    'yaml_file': YamlFileField
}


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
            field_class = TYPE_MAP.get(field_params['type'], None)
            if field_class:
                label = field_params['label'] if 'label' in field_params else field_name
                jsvalidators = field_params['validators'] if 'validators' in field_params else {}
                field = field_class(label, switchtag=switchtag, jsvalidators=jsvalidators)
                setattr(cls, field_name, field)
