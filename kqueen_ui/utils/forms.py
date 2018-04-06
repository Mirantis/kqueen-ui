from collections import OrderedDict
from flask_wtf import FlaskForm
from kqueen_ui.utils.fields import (
    EmailField,
    FileField,
    IntegerField,
    JsonFileField,
    PasswordField,
    SelectField,
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
    'select': SelectField,
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
        # Sort engine parameters by order if set and by name in the second turn
        fields = OrderedDict(sorted(ctx.items(), key=lambda k: (k[1].get('order', 0), k[0])))

        for field_name, field_params in fields.items():
            field_class = TYPE_MAP.get(field_params['type'], None)
            if field_class:
                label = field_params['label'] if 'label' in field_params else field_name
                jsvalidators = field_params['validators'] if 'validators' in field_params else {}
                field_kwargs = {
                    'switchtag': switchtag,
                    'jsvalidators': jsvalidators
                }
                if field_class == SelectField:
                    field_kwargs['choices'] = field_params.get('choices', [])
                if 'default' in field_params:
                    field_kwargs['default'] = field_params['default']
                field = field_class(label, **field_kwargs)
                setattr(cls, field_name, field)
