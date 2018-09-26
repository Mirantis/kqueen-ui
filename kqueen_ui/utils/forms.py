from collections import OrderedDict
from flask_wtf import FlaskForm
from kqueen_ui.utils.fields import (
    CheckboxField,
    EmailField,
    FileField,
    IntegerField,
    JsonFileField,
    PasswordField,
    SelectField,
    StringField,
    TextAreaField,
    YamlFileField,
    ParametersField
)


TYPE_MAP = {
    'checkbox': CheckboxField,
    'email': EmailField,
    'file': FileField,
    'integer': IntegerField,
    'json_file': JsonFileField,
    'password': PasswordField,
    'select': SelectField,
    'text': StringField,
    'text_area': TextAreaField,
    'yaml_file': YamlFileField,
    'parameters': ParametersField
}


class FlaskExtendableForm(FlaskForm):

    @classmethod
    def append_fields(cls, ctx, switchtag=None, cluster_fields=False):
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
                label = field_params.get('label', field_name)
                jsvalidators = field_params.get('validators', {})
                help_message = field_params.get('help_message')
                field_kwargs = {
                    'switchtag': switchtag,
                    'jsvalidators': jsvalidators,
                    'help_message': help_message
                }
                if cluster_fields:
                    field_kwargs['cluster_field'] = True
                    # Submit form even if not all default values are set for cluster
                    if 'validators' in field_params:
                        if 'required' in field_params['validators']:
                            del field_params['validators']['required']
                if field_class == SelectField:
                    field_kwargs['choices'] = field_params.get('choices', [])
                additional_fields = ['default', 'class_name', 'placeholder']
                for field in additional_fields:
                    if field in field_params:
                        field_kwargs[field] = field_params[field]

                field = field_class(label=label, **field_kwargs)
                setattr(cls, field_name, field)

    @classmethod
    def set_default_values(cls, provisioner_id, fields_with_values):
        for field_name, value in fields_with_values.items():
            attr_name = field_name + '__' + provisioner_id
            form_field = getattr(cls, attr_name, None)
            if form_field:
                form_field.kwargs['default'] = value
