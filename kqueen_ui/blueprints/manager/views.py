from .forms import MemberChangeRoleForm, MemberCreateForm, OrganizationCreateForm
from .forms import ROLE_CHOICES
from datetime import datetime
from flask import Blueprint, current_app as app, flash, jsonify, redirect, render_template, request, session, url_for
from flask_babel import format_datetime
from flask_mail import Mail, Message
from kqueen_ui.api import get_kqueen_client
from kqueen_ui.auth import generate_confirmation_token
from kqueen_ui.blueprints.ui.utils import generate_password, sanitize_resource_metadata
from kqueen_ui.generic_views import KQueenView
from kqueen_ui.utils.loggers import user_prefix
from kqueen_ui.utils.wrappers import superadmin_required
from slugify import slugify

import logging

logger = logging.getLogger('kqueen_ui')
user_logger = logging.getLogger('user')
mail = Mail()
manager = Blueprint('manager', __name__, template_folder='templates')


##############
# Interceptors
##############

@manager.before_request
def test_token():
    if session.get('user', None) and not app.testing:
        client = get_kqueen_client(token=session['user']['token'])
        organization_id = session['user']['organization']['id']
        response = client.organization.policy(organization_id)
        if response.status == 401:
            flash('Session expired, please log in again.', 'warning')
            del session['user']
            if 'policy' in session:
                del session['policy']
        elif response.status == -1:
            flash('Backend is unavailable at this time, please try again later.', 'danger')
            del session['user']
            if 'policy' in session:
                del session['policy']
        policy = response.data
        if policy and isinstance(policy, dict):
            session['policy'] = policy


###############
# General Views
###############

class Overview(KQueenView):
    decorators = [superadmin_required]
    methods = ['GET']

    def handle(self):
        organizations = self.kqueen_request('organization', 'list')
        organizations.sort(key=lambda k: (k['namespace'], k['created_at'], k['name']))
        for organization in organizations:
            organization['created_at'] = format_datetime(organization['created_at'])
        return render_template('manager/overview.html', organizations=organizations)


class DataClusters(KQueenView):
    decorators = [superadmin_required]
    methods = ['GET']

    def handle(self):
        clusters = self.kqueen_request('cluster', 'list', fnkwargs={'all_namespaces': True})
        clusters, _, _ = sanitize_resource_metadata(session, clusters, [])
        clusters.sort(key=lambda k: (k['_namespace'], k['created_at'], k['name']))
        data = {
            'response': 200,
            'body': render_template('manager/partial/cluster_table.html', clusters=clusters)
        }
        return jsonify(data)


class DataProvisioners(KQueenView):
    decorators = [superadmin_required]
    methods = ['GET']

    def handle(self):
        provisioners = self.kqueen_request('provisioner', 'list', fnkwargs={'all_namespaces': True})
        _, provisioners, _ = sanitize_resource_metadata(session, [], provisioners)
        provisioners.sort(key=lambda k: (k['_namespace'], k['created_at'], k['name']))
        data = {
            'response': 200,
            'body': render_template('manager/partial/provisioner_table.html', provisioners=provisioners)
        }
        return jsonify(data)


class OrganizationDelete(KQueenView):
    decorators = [superadmin_required]
    methods = ['GET']
    validation_hint = 'uuid'

    def handle(self, organization_id):
        organization = self.kqueen_request('organization', 'get', fnargs=(organization_id,))
        deletable = self.kqueen_request('organization', 'deletable', fnargs=(organization_id,))
        if not deletable.get('deletable', False):
            resources = ', '.join(['{} {}'.format(r['object'].lower(), r['name']) for r in deletable.get('remaining', [])])
            flash('Cannot delete organization {}, before deleting its resources: {}'.format(organization['name'], resources), 'warning')
            return redirect(request.environ.get('HTTP_REFERER', url_for('manager.overview')))
        self.kqueen_request('organization', 'delete', fnargs=(organization_id,))
        msg = 'Organization {} successfully deleted.'.format(organization['name'])
        user_logger.debug('{}:{}'.format(user_prefix(session), msg))
        flash(msg, 'success')
        return redirect(request.environ.get('HTTP_REFERER', url_for('manager.overview')))


class OrganizationCreate(KQueenView):
    decorators = [superadmin_required]
    methods = ['GET', 'POST']

    def handle(self):
        form = OrganizationCreateForm()
        if form.validate_on_submit():
            organization_kw = {
                'name': form.organization_name.data,
                'namespace': slugify(form.organization_name.data),
                'created_at': datetime.utcnow()
            }
            organization = self.kqueen_request('organization', 'create', fnargs=(organization_kw,))
            msg = 'Organization {} successfully created.'.format(organization['name'])
            user_logger.debug('{}:{}'.format(user_prefix(session), msg))
            flash(msg, 'success')
            return redirect(url_for('manager.overview'))
        return render_template('manager/organization_create.html', form=form)


class OrganizationDetail(KQueenView):
    decorators = [superadmin_required]
    methods = ['GET']

    def handle(self, organization_id):
        # session data
        user_id = session['user']['id']
        # backend resources
        organization = self.kqueen_request('organization', 'get', fnkwargs={'uuid': organization_id})
        users = self.kqueen_request('user', 'list')
        members = [
            u
            for u
            in users
            if u['organization']['id'] == organization_id and u['id'] != user_id
        ]
        # sort members by date
        members.sort(key=lambda k: (k['created_at'], k['username']))

        # Patch members until we actually have these data for realsies
        for member in members:
            member['state'] = 'Active' if member['active'] else 'Disabled'
            member['role'] = member['role'].capitalize()
            if 'email' not in member:
                member['email'] = '-'
            if 'created_at' in member:
                member['created_at'] = format_datetime(member['created_at'])

        return render_template('manager/organization_detail.html',
                               organization=organization,
                               members=members)


class MemberCreate(KQueenView):
    decorators = [superadmin_required]
    methods = ['GET', 'POST']

    def handle(self, organization_id):
        form = MemberCreateForm()
        if form.validate_on_submit():
            user_kw = {
                'username': form.email.data,
                'email': form.email.data,
                'password': generate_password(),
                'organization': 'Organization:{}'.format(organization_id),
                'created_at': datetime.utcnow(),
                'role': form.role.data,
                'active': True,
                'metadata': {}
            }
            user = self.kqueen_request('user', 'create', fnkwargs={'payload': user_kw})

            # Init mail handler
            mail.init_app(app)
            token = generate_confirmation_token(user['email'])
            html = render_template(
                'ui/email/user_invitation.html',
                username=user['username'],
                token=token,
                organization=user['organization']['name']
            )
            msg = Message(
                '[KQueen] Organization invitation',
                recipients=[user['email']],
                html=html
            )
            try:
                mail.send(msg)
            except Exception as e:
                self.logger('error', repr(e))
                self.kqueen_request('user', 'delete', fnargs={'uuid', user['id']})
                flash('Could not send invitation e-mail, please try again later.', 'danger')
                return render_template('manager/member_create.html', form=form)

            msg = 'Member {} successfully added.'.format(user['username'])
            user_logger.debug('{}:{}'.format(user_prefix(session), msg))
            flash(msg, 'success')
            return redirect(url_for('manager.organization_detail', organization_id=organization_id))
        return render_template('manager/member_create.html', form=form)


class MemberChangeRole(KQueenView):
    decorators = [superadmin_required]
    methods = ['GET', 'POST']

    def handle(self, organization_id, user_id):
        user = self.kqueen_request('user', 'get', fnkwargs={'uuid': user_id})
        form = MemberChangeRoleForm()
        form.role.choices = tuple([rl for rl in ROLE_CHOICES if user['role'] not in rl])
        if form.validate_on_submit():
            user['role'] = form.role.data
            self.kqueen_request('user', 'update', fnkwargs={'uuid': user_id, 'payload': user})
            msg = 'Role of {} has been successfully updated.'.format(user['username'])
            user_logger.debug('{}:{}'.format(user_prefix(session), msg))
            flash(msg, 'success')
            return redirect(url_for('manager.organization_detail', organization_id=organization_id))
        return render_template('manager/member_change_role.html', form=form, username=user['username'])


manager.add_url_rule('/', view_func=Overview.as_view('overview'))
manager.add_url_rule('/data/clusters', view_func=DataClusters.as_view('data_clusters'))
manager.add_url_rule('/data/provisioners', view_func=DataProvisioners.as_view('data_provisioners'))
manager.add_url_rule('/organization/create', view_func=OrganizationCreate.as_view('organization_create'))
manager.add_url_rule('/organization/<organization_id>/delete', view_func=OrganizationDelete.as_view('organization_delete'))
manager.add_url_rule('/organization/<organization_id>/detail', view_func=OrganizationDetail.as_view('organization_detail'))
manager.add_url_rule('/organization/<organization_id>/member/create', view_func=MemberCreate.as_view('member_create'))
manager.add_url_rule('/organization/<organization_id>/member/<user_id>/changerole', view_func=MemberChangeRole.as_view('member_change_role'))
