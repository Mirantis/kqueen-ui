from flask_wtf.file import FileField as WTFileField
from werkzeug.datastructures import FileStorage
from wtforms import (
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


class JsonFileField(FileField):

    def process_formdata(self, valuelist):
        super(JsonFileField, self).process_formdata(valuelist)
        if self.data and isinstance(self.data, FileStorage):
            try:
                data = self.data.read()
                self.data = json.loads(data.decode('utf-8'))
            except Exception as e:
                self.data = {}
                logger.error('Could not load JSON file: {}'.format(repr(e)))


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


class YamlFileField(FileField):

    def process_formdata(self, valuelist):
        super(YamlFileField, self).process_formdata(valuelist)
        if self.data and isinstance(self.data, FileStorage):
            try:
                self.data = yaml.load(self.data.stream)
            except Exception as e:
                self.data = {}
                logger.error('Could not load YAML file: {}'.format(repr(e)))
