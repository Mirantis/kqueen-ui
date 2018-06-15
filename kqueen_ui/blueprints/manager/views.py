from .forms import MemberChangeRoleForm, MemberCreateForm, OrganizationCreateForm
from .forms import ROLE_CHOICES
from datetime import datetime
from flask import Blueprint, current_app as app, flash, jsonify, redirect, render_template, request, session, url_for
from flask_babel import format_datetime
from kqueen_ui.api import get_kqueen_client
from kqueen_ui.auth import generate_confirmation_token
from kqueen_ui.blueprints.ui.utils import generate_password, sanitize_resource_metadata
from kqueen_ui.generic_views import KQueenView
from kqueen_ui.exceptions import KQueenAPIException
from kqueen_ui.utils.email import EmailMessage
from kqueen_ui.utils.loggers import user_prefix
from kqueen_ui.utils.wrappers import superadmin_required
from slugify import slugify

from ...blueprints.ui.utils import form_page_ranges

import json
import logging

logger = logging.getLogger('kqueen_ui')
user_logger = logging.getLogger('user')

manager = Blueprint('manager', __name__, template_folder='templates')


def get_page(args, page_arg):
    try:
        return int(args.get(page_arg, 1))
    except ValueError:
        return 1


def get_pages_count(objects_total, objects_per_page):
    full_pages = objects_total // objects_per_page
    return full_pages + 1 if objects_total % objects_per_page else full_pages


def handle_exception_for_ajax(e):
    try:
        error_details = json.loads(str(e))
        data = {
            'response': error_details['code'],
            'body': error_details['description']
        }
    except json.JSONDecodeError:
        data = {
            'response': 'unknown',
            'body': str(e)
        }
    return jsonify(data)

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

        return render_template('manager/overview.html',
                               organizations=organizations,
                               c_page=get_page(request.args, 'c_page'),
                               p_page=get_page(request.args, 'p_page'))


class DataClusters(KQueenView):
    decorators = [superadmin_required]
    methods = ['GET']
    objects_per_page = 20

    def handle(self):
        page = get_page(request.args, 'c_page')
        try:
            clusters = self.kqueen_request(
                'cluster', 'list',
                fnkwargs={'all_namespaces': True, 'page': page, 'per_page': self.objects_per_page}
            )
        except Exception as e:
            return handle_exception_for_ajax(e)
        cluster_pages = get_pages_count(clusters['total'], self.objects_per_page)
        clusters, _ = sanitize_resource_metadata(session, clusters['items'], [])
        clusters.sort(key=lambda k: k['_namespace'])

        data = {
            'response': 200,
            'body': render_template('manager/partial/cluster_table.html',
                                    clusters=clusters,
                                    cluster_pages=cluster_pages,
                                    current_cluster_page=page,
                                    current_provisioner_page=get_page(request.args, 'p_page'),
                                    form_page_ranges=form_page_ranges)
        }
        return jsonify(data)


class DataProvisioners(KQueenView):
    decorators = [superadmin_required]
    methods = ['GET']
    objects_per_page = 20

    def handle(self):
        page = get_page(request.args, 'p_page')
        try:
            provisioners = self.kqueen_request(
                'provisioner', 'list',
                fnkwargs={'all_namespaces': True, 'page': page, 'per_page': self.objects_per_page}
            )
        except Exception as e:
            return handle_exception_for_ajax(e)
        provisioner_pages = get_pages_count(provisioners['total'], self.objects_per_page)
        _, provisioners = sanitize_resource_metadata(session, [], provisioners['items'])
        provisioners.sort(key=lambda k: k['_namespace'])
        data = {
            'response': 200,
            'body': render_template('manager/partial/provisioner_table.html',
                                    provisioners=provisioners,
                                    provisioner_pages=provisioner_pages,
                                    current_cluster_page=get_page(request.args, 'c_page'),
                                    current_provisioner_page=page,
                                    form_page_ranges=form_page_ranges)
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
            try:
                organization = self.kqueen_request('organization', 'create', fnargs=(organization_kw,))
            except KQueenAPIException:
                return redirect(url_for('manager.overview'))
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
        form_cls = MemberCreateForm

        auth_config = self.kqueen_request('configuration', 'auth')

        for auth_type, options in auth_config.items():
            ui_parameters = options['ui_parameters']
            # Add tag to field names to enable dynamic field switching
            ui_parameters = {k + '__' + auth_type: v for k, v in ui_parameters.items()}
            form_cls.append_fields(ui_parameters, switchtag=auth_type)

        form = form_cls()
        form.auth_method.choices = [(k, v['name']) for k, v in auth_config.items()]
        if form.validate_on_submit():
            # Filter out populated tagged fields and get their data
            try:
                ui_filled_parameters = {
                    k.split('__')[0]: v.data
                    for (k, v)
                    in form._fields.items()
                    if (hasattr(v, 'switchtag') and v.switchtag) and form.auth_method.data in k
                }
            except Exception as e:
                msg = 'Failed to invite user: Invalid parameters.'
                user_logger.exception('{}:{}'.format(user_prefix(session), msg))
                flash(msg, 'danger')
                render_template('ui/user_invite.html', form=form)

            chosen_auth_type = form.auth_method.data
            username_field_descr = auth_config[chosen_auth_type]['ui_parameters']['username']
            username = ui_filled_parameters['username']

            user_kw = {
                'username': username,
                'password': generate_password() if username_field_descr.get('generate_password', True) else '',
                'email': username if username_field_descr['type'] == 'email' else '',
                'organization': 'Organization:{}'.format(organization_id),
                'role': form.role.data,
                'created_at': datetime.utcnow(),
                'auth': chosen_auth_type,
                'active': username_field_descr.get('active', True),
                'metadata': {}
            }
            logger.debug('User {} from {} invited.'.format(user_kw['username'], user_kw['organization']))
            user = self.kqueen_request('user', 'create', fnkwargs={'payload': user_kw})

            # send mail
            notify = username_field_descr.get('notify')
            if notify:
                logger.debug('User {} from {} with id {} will be notified '
                             'through email.'.format(user_kw['username'], user_kw['organization'], user['id']))
                token = generate_confirmation_token(user['email'])
                html = render_template(
                    'ui/email/user_invitation.html',
                    username=user['username'],
                    token=token,
                    organization=user['organization']['name'],
                    year=datetime.utcnow().year
                )
                email = EmailMessage(
                    '[KQueen] Organization invitation',
                    recipients=[user['email']],
                    html=html
                )
                try:
                    email.send()
                except Exception:
                    logger.exception('User {} from {} with id {} will be removed.'.format(user_kw['username'],
                                                                                          user_kw['organization'],
                                                                                          user['id']))
                    self.kqueen_request('user', 'delete', fnargs=(user['id'],))
                    flash('Could not send invitation e-mail, please try again later.', 'danger')
                    return render_template('manager/member_create.html', form=form, organization_id=organization_id)

            logger.debug('User {} from {} created with id {}.'.format(user_kw['username'],
                                                                      user_kw['organization'],
                                                                      user['id']))

            msg = 'Member {} successfully added.'.format(user['username'])
            user_logger.debug('{}:{}'.format(user_prefix(session), msg))
            flash(msg, 'success')
            return redirect(url_for('manager.organization_detail', organization_id=organization_id))
        return render_template('manager/member_create.html', form=form, organization_id=organization_id)


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
        return render_template('manager/member_change_role.html', form=form, username=user['username'], organization_id=organization_id)


manager.add_url_rule('/', view_func=Overview.as_view('overview'))
manager.add_url_rule('/data/clusters', view_func=DataClusters.as_view('data_clusters'))
manager.add_url_rule('/data/provisioners', view_func=DataProvisioners.as_view('data_provisioners'))
manager.add_url_rule('/organization/create', view_func=OrganizationCreate.as_view('organization_create'))
manager.add_url_rule('/organization/<organization_id>/delete', view_func=OrganizationDelete.as_view('organization_delete'))
manager.add_url_rule('/organization/<organization_id>/detail', view_func=OrganizationDetail.as_view('organization_detail'))
manager.add_url_rule('/organization/<organization_id>/member/create', view_func=MemberCreate.as_view('member_create'))
manager.add_url_rule('/organization/<organization_id>/member/<user_id>/changerole', view_func=MemberChangeRole.as_view('member_change_role'))
