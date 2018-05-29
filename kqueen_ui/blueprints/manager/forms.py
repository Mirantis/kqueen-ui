from flask_wtf import FlaskForm
from kqueen_ui.utils.forms import FlaskExtendableForm
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
        return True


class MemberCreateForm(FlaskExtendableForm):
    auth_method = SelectField('Authentication Method', choices=[], switch=True)
    role = SelectField('Role', choices=ROLE_CHOICES)


class MemberChangeRoleForm(FlaskForm):
    role = SelectField('Role', choices=ROLE_CHOICES)
