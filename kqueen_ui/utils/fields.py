from flask_wtf.file import FileField as WTFileField
from wtforms import (
    BooleanField as WTBooleanField,
    PasswordField as WTPasswordField,
    SelectField as WTSelectField,
    StringField as WTStringField,
    TextAreaField as WTTextAreaField
)
from wtforms.fields.html5 import (
    EmailField as WTEmailField,
    IntegerField as WTIntegerField
)

import json
import logging
import yaml

logger = logging.getLogger('kqueen_ui')


# MIXINS

class SelectableMixin:
    switchtag = None
    jsvalidators = {}

    def __init__(self, *args, **kwargs):
        self.switchtag = kwargs.pop('switchtag', None)
        self.jsvalidators = kwargs.pop('jsvalidators', None)
        self.class_name = kwargs.pop('class_name', '')
        self.placeholder = kwargs.pop('placeholder', '')
        super(SelectableMixin, self).__init__(*args, **kwargs)


# FIELDS

class EmailField(SelectableMixin, WTEmailField):
    pass


class FileField(SelectableMixin, WTFileField):
    pass


class IntegerField(SelectableMixin, WTIntegerField):
    def _value(self):
        # potentially dangerous hack which changes empty value to
        # zero integer, so we can submit hidden integer fields
        value = super(IntegerField, self)._value()
        return value or 0


class EditableFileField(SelectableMixin, WTTextAreaField):
    def __init__(self, *args, **kwargs):
        super(EditableFileField, self).__init__(*args, **kwargs)
        self.read_from_file = True
        self.placeholder = 'Put your data right here or select a file'
        self.class_name += 'editable-file'


class JsonFileField(EditableFileField):
    def __init__(self, *args, **kwargs):
        super(JsonFileField, self).__init__(*args, **kwargs)
        self._data = ''  # string representation of loaded json
        self.accept_files = '.json'

    def _value(self):
        return self._data

    def process_formdata(self, valuelist):
        super(JsonFileField, self).process_formdata(valuelist)
        if self.data:
            try:
                self._data = self.data
                self.data = json.loads(self.data)
            except Exception:
                msg = 'Provided file is not a JSON'
                logger.exception(msg)
                raise ValueError(msg)


class PasswordField(SelectableMixin, WTPasswordField):
    pass


class SelectField(SelectableMixin, WTSelectField):
    switch = False

    def __init__(self, *args, **kwargs):
        self.switch = kwargs.pop('switch', False)
        super(SelectField, self).__init__(*args, **kwargs)


class CheckboxField(SelectableMixin, WTBooleanField):
    def __init__(self, *args, **kwargs):
        self.checkbox_text = kwargs.pop('checkbox_text', '')
        super(CheckboxField, self).__init__(*args, **kwargs)


class StringField(SelectableMixin, WTStringField):
    pass


class TextAreaField(SelectableMixin, WTTextAreaField):
    pass


class YamlFileField(EditableFileField):
    def process_formdata(self, valuelist):
        super(YamlFileField, self).process_formdata(valuelist)
        if self.data:
            try:
                yaml.load(self.data)
            except Exception:
                msg = 'Provided file is not a YAML'
                logger.exception(msg)
                raise ValueError(msg)
