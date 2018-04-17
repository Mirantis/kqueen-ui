from flask import session
from flask_wtf import FlaskForm
from kqueen_ui.api import get_kqueen_client
from kqueen_ui.utils.forms import FlaskExtendableForm
from slugify import slugify
from kqueen_ui.utils.fields import SelectField, StringField
from wtforms.validators import DataRequired

ROLE_CHOICES = (
    ('member', 'Member'),
    ('admin', 'Admin')
)


class OrganizationCreateForm(FlaskForm):
    organization_name = StringField('Organization Name', validators=[DataRequired()])

    def validate(self):
        if not FlaskForm.validate(self):
            return False

        # Cannot allow this Organization name, because it would cause issues on backend
        if self.organization_name.data == 'global':
            self.organization_name.errors.append('Cannot allow this Organization name for secret reasons, shush.')
            return False

        # TODO: remove these uniqueness checks after introduction of unique constraint
        # in ETCD storage class on backend
        client = get_kqueen_client(token=session['user']['token'])
        # Check if organization exists on backend
        response = client.organization.list()
        if response.status > 200:
            self.organization_name.errors.append('Can not contact backend at this time.')
            return False
        organizations = response.data
        organization_names = [org['name'] for org in organizations]
        organization_namespaces = [o['namespace'] for o in organizations]
        if self.organization_name.data in organization_names or slugify(self.organization_name.data) in organization_namespaces:
            self.organization_name.errors.append('Organization {} already exists.'.format(self.organization_name.data))
            return False

        return True


class MemberCreateForm(FlaskExtendableForm):
    auth_method = SelectField('Authentication Method', choices=[], switch=True)
    role = SelectField('Role', choices=ROLE_CHOICES)

    # TODO: Add general email field validator


class MemberChangeRoleForm(FlaskForm):
    role = SelectField('Role', choices=ROLE_CHOICES)
