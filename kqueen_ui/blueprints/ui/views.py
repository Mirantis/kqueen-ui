from datetime import datetime
from flask import (current_app as app, abort, Blueprint, flash, jsonify, redirect,
                   render_template, request, session, url_for)
from flask_mail import Mail, Message
from flask.ext.babel import format_datetime
from kqueen_ui.api import get_kqueen_client
from kqueen_ui.auth import authenticate, confirm_token, generate_confirmation_token
from kqueen_ui.generic_views import KQueenView
from kqueen_ui.utils.wrappers import login_required
from uuid import UUID

from .forms import (ClusterCreateForm, ProvisionerCreateForm, ClusterApplyForm,
                    ChangePasswordForm, UserInviteForm, RequestPasswordResetForm,
                    PasswordResetForm)
from .utils import generate_password, prettify_engine_name, status_for_cluster_detail

import logging

logger = logging.getLogger(__name__)
mail = Mail()

ui = Blueprint('ui', __name__, template_folder='templates')


##############
# Interceptors
##############

@ui.before_request
def test_token():
    if session.get('user', None) and not app.testing:
        client = get_kqueen_client(token=session['user']['token'])
        response = client.user.whoami()
        if response.status == 401:
            flash('Session expired, please log in again.', 'warning')
            del session['user']
        elif response.status == -1:
            flash('Backend is unavailable at this time, please try again later.', 'danger')
            del session['user']


#############
# Table Views
#############

# Main

@ui.route('/')
@login_required
def index():
    clusters = []
    healthy_clusters = 0
    provisioners = []
    healthy_provisioners = 0

    if session.get('user', {}).get('token', None):
        client = get_kqueen_client(token=session['user']['token'])
        _clusters = client.cluster.list()
        clusters = _clusters.data
        _provisioners = client.provisioner.list()
        provisioners = _provisioners.data

    for cluster in clusters:
        if 'state' in cluster:
            if app.config['CLUSTER_ERROR_STATE'] != cluster['state']:
                healthy_clusters = healthy_clusters + 1
        if 'created_at' in cluster:
            cluster['created_at'] = format_datetime(cluster['created_at'])

    # sort clusters by date
    if isinstance(clusters, list):
        clusters.sort(key=lambda k: (k['created_at'], k['name']))

    for provisioner in provisioners:
        provisioner['engine_name'] = prettify_engine_name(provisioner['engine'])
        if 'state' in provisioner:
            if app.config['PROVISIONER_ERROR_STATE'] not in provisioner['state']:
                healthy_provisioners = healthy_provisioners + 1
        if 'created_at' in provisioner:
            provisioner['created_at'] = format_datetime(provisioner['created_at'])

    # sort provisioners by date
    if isinstance(provisioners, list):
        provisioners.sort(key=lambda k: (k['created_at'], k['name']))

    cluster_health = 100
    if healthy_clusters and clusters:
        cluster_health = int((healthy_clusters / len(clusters)) * 100)

    provisioner_health = 100
    if healthy_provisioners and provisioners:
        provisioner_health = int((healthy_provisioners / len(provisioners)) * 100)

    overview = {
        'cluster_count': len(clusters),
        'cluster_health': cluster_health,
        'provisioner_count': len(provisioners),
        'provisioner_health': provisioner_health,
    }
    return render_template('ui/index.html',
                           overview=overview,
                           clusters=clusters,
                           provisioners=provisioners)


@ui.route('/organizations/manage')
@login_required
def organization_manage():
    try:
        client = get_kqueen_client(token=session['user']['token'])
        _organization = client.organization.get(session['user']['organization']['id'])
        organization = _organization.data
        _users = client.user.list()
        users = _users.data
        members = [
            u
            for u
            in users
            if u['organization']['id'] == session['user']['organization']['id'] and u['id'] != session['user']['id']
        ]
        # Patch members until we actually have these data for realsies
        for member in members:
            member['role'] = 'Member'
            member['state'] = 'Active' if member['active'] else 'Disabled'
            if 'email' not in member:
                member['email'] = '-'
            if 'created_at' in member:
                member['created_at'] = format_datetime(member['created_at'])
        # sort members by date
        members.sort(key=lambda k: (k['created_at'], k['username']))
    except Exception as e:
        logger.error('organization_manage view: {}'.format(repr(e)))
        organization = {}
        members = []

    return render_template('ui/organization_manage.html',
                           organization=organization,
                           members=members)


@ui.route('/clusters/<cluster_id>/detail', methods=['GET', 'POST'])
@login_required
def cluster_detail(cluster_id):
    try:
        UUID(cluster_id, version=4)
    except ValueError:
        logger.warning('cluster_detail view: invalid uuid {}'.format(str(cluster_id)))
        abort(404)

    client = get_kqueen_client(token=session['user']['token'])
    _cluster = client.cluster.get(cluster_id)
    cluster = _cluster.data
    if not cluster:
        logger.warning('cluster_detail view: {} not found'.format(str(cluster_id)))
        abort(404)

    _status_data = {}
    state_class = 'info'
    state = cluster['state']
    if state == app.config['CLUSTER_OK_STATE']:
        state_class = 'success'
        try:
            _status = client.cluster.status(cluster_id)
            _status_data = _status.data
        except Exception as e:
            logger.error('cluster_detail view: {}'.format(repr(e)))
            flash('Unable to get information about cluster', 'danger')
    elif state == app.config['CLUSTER_ERROR_STATE']:
        state_class = 'danger'

    status = status_for_cluster_detail(_status_data)

    form = ClusterApplyForm()
    if form.validate_on_submit():
        # TODO: implement this after API supports apply call
        # obj.apply(form.apply.data)
        pass

    return render_template(
        'ui/cluster_detail.html',
        cluster=cluster,
        status=status,
        state_class=state_class,
        form=form
    )


@ui.route('/catalog')
@login_required
def catalog():
    return render_template('ui/catalog.html')


# Auth

@ui.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        user, _error = authenticate(request.form['username'], request.form['password'])
        if user:
            session['user'] = user
            flash('You were logged in', 'success')
            next_url = request.form.get('next', '')
            if next_url:
                return redirect(next_url)
            return redirect(url_for('ui.index'))
        elif _error:
            if _error['status'] == 401:
                error = 'Invalid credentials.'
            else:
                error = 'Could not contact authentication backend, please try again later.'
    return render_template('ui/login.html', error=error)


@ui.route('/logout')
@login_required
def logout():
    del session['user']
    flash('You were logged out', 'success')
    return redirect(url_for('ui.index'))


#
# Form Views
#

# User

class UserInvite(KQueenView):
    decorators = [login_required]
    methods = ['GET', 'POST']

    def handle(self):
        form = UserInviteForm()
        if form.validate_on_submit():
            organization = 'Organization:{}'.format(session['user']['organization']['id'])
            password = generate_password()
            user_kw = {
                'username': form.email.data,
                'password': password,
                'email': form.email.data,
                'organization': organization,
                'created_at': datetime.utcnow(),
                'active': True
            }
            user = self.kqueen_request('user', 'create', fnargs=(user_kw,))

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
                self.kqueen_request('user', 'delete', fnargs=(user['id'],))
                flash('Could not send invitation e-mail, please try again later.', 'danger')
                return render_template('ui/user_invite.html', form=form)

            flash('User {} successfully created.'.format(user['username']), 'success')
            return redirect(url_for('ui.organization_manage'))
        return render_template('ui/user_invite.html', form=form)


class UserDelete(KQueenView):
    decorators = [login_required]
    methods = ['GET']
    validation_hint = 'uuid'

    def handle(self, user_id):
        user = self.kqueen_request('user', 'get', fnargs=(user_id,))
        self.kqueen_request('user', 'delete', fnargs=(user_id,))
        flash('User {} successfully deleted.'.format(user['username']), 'success')
        return redirect(request.environ['HTTP_REFERER'])


class UserChangePassword(KQueenView):
    decorators = [login_required]
    methods = ['GET', 'POST']

    def handle(self, *args, **kwargs):
        form = ChangePasswordForm()
        if form.validate_on_submit():
            user_id = session['user']['id']
            user = self.kqueen_request('user', 'get', fnargs=(user_id,))
            user['password'] = form.password_1.data
            self.kqueen_request('user', 'update', fnargs=(user_id, user))
            flash('Password successfully updated. Please log in again.', 'success')
            return redirect(url_for('ui.logout'))
        return render_template('ui/user_change_password.html', form=form)


class UserResetPassword(KQueenView):
    methods = ['GET', 'POST']

    def handle(self, token):
        email = confirm_token(token)
        if not email:
            flash('Password reset link is invalid or has expired.', 'danger')
            return redirect(url_for('ui.index'))

        users = self.kqueen_request('user', 'list', service=True)
        # TODO: this logic realies heavily on unique emails, this is not the case on backend right now
        # change this logic after unique contraint is introduced to backend
        filtered = [u for u in users if u.get('email', None) == email]
        if len(filtered) == 1:
            user = filtered[0]
            form = PasswordResetForm()
            if form.validate_on_submit():
                user['password'] = form.password_1.data
                self.kqueen_request('user', 'update', fnargs=(user['id'], user), service=True)
                flash('Password successfully updated.', 'success')
                return redirect(url_for('ui.login'))
            return render_template('ui/user_reset_password.html', form=form)
        else:
            flash('Could not match user to given e-mail.', 'danger')
        return redirect(url_for('ui.index'))


class UserRequestResetPassword(KQueenView):
    methods = ['GET', 'POST']

    def handle(self):
        form = RequestPasswordResetForm()
        if form.validate_on_submit():
            # Init mail handler
            mail.init_app(app)
            token = generate_confirmation_token(form.email.data)
            html = render_template('ui/email/user_request_password_reset.html', token=token)
            msg = Message(
                '[KQueen] Password reset',
                recipients=[form.email.data],
                html=html
            )
            try:
                mail.send(msg)
            except Exception as e:
                self.logger('error', repr(e))
                flash('Could not send password reset e-mail, please try again later.', 'danger')
            flash('Password reset link was sent to your e-mail address.', 'success')
            return redirect(url_for('ui.index'))
        return render_template('ui/user_request_password_reset.html', form=form)


ui.add_url_rule('/users/invite', view_func=UserInvite.as_view('user_invite'))
ui.add_url_rule('/users/<user_id>/delete', view_func=UserDelete.as_view('user_delete'))
ui.add_url_rule('/users/changepw', view_func=UserChangePassword.as_view('user_change_password'))
ui.add_url_rule('/users/resetpw/<token>', view_func=UserResetPassword.as_view('user_reset_password'))
ui.add_url_rule('/users/requestresetpw', view_func=UserRequestResetPassword.as_view('user_request_reset_password'))


# Provisioner

class ProvisionerCreate(KQueenView):
    decorators = [login_required]
    methods = ['GET', 'POST']

    def handle(self):
        # Get engines with parameters
        engines = self.kqueen_request('provisioner', 'engines')

        # Append tagged parameter fields to form
        form_cls = ProvisionerCreateForm
        for engine in engines:
            _engine_parameters = engine['parameters']['provisioner']
            engine_parameters = {
                k + '__' + prettify_engine_name(engine['name']): v
                for (k, v)
                in _engine_parameters.items()
            }
            form_cls.append_fields(engine_parameters, switchtag=engine['name'])

        # Instantiate form and populate engine choices
        form = form_cls()
        form.engine.choices = [(e['name'], prettify_engine_name(e['name'])) for e in engines]

        if form.validate_on_submit():
            try:
                # Filter out populated tagged fields and get their data
                parameters = {
                    k.split('__')[0]: v.data
                    for (k, v)
                    in form._fields.items()
                    if (hasattr(v, 'switchtag') and v.switchtag) and prettify_engine_name(form.engine.data) in k
                }
            except Exception as e:
                self.logger('error', repr(e))
                flash('Invalid provisioner parameters.', 'danger')
                render_template('ui/provisioner_create.html', form=form)

            provisioner_kw = {
                'name': form.name.data,
                'engine': form.engine.data,
                'state': app.config['PROVISIONER_UNKNOWN_STATE'],
                'parameters': parameters,
                'created_at': datetime.utcnow()
            }
            provisioner = self.kqueen_request('provisioner', 'create', fnargs=(provisioner_kw,))
            flash('Provisioner {} successfully created.'.format(provisioner['name']), 'success')
            return redirect('/')
        return render_template('ui/provisioner_create.html', form=form)


class ProvisionerDelete(KQueenView):
    decorators = [login_required]
    methods = ['GET']
    validation_hint = 'uuid'

    def handle(self, provisioner_id):
        # TODO: block deletion of used provisioner on backend, not here
        clusters = self.kqueen_request('cluster', 'list')
        provisioner = self.kqueen_request('provisioner', 'get', fnargs=(provisioner_id,))
        used_provisioners = [p['id'] for p in [c['provisioner'] for c in clusters]]

        if provisioner_id not in used_provisioners:
            self.kqueen_request('provisioner', 'delete', fnargs=(provisioner_id,))
            flash('Provisioner {} successfully deleted.'.format(provisioner['name']), 'success')
        else:
            flash('Provisioner {} is in use, cannot delete.'.format(provisioner['name']), 'warning')

        return redirect('/')


ui.add_url_rule('/provisioners/create', view_func=ProvisionerCreate.as_view('provisioner_create'))
ui.add_url_rule('/provisioners/<provisioner_id>/delete', view_func=ProvisionerDelete.as_view('provisioner_delete'))


# Cluster

class ClusterCreate(KQueenView):
    decorators = [login_required]
    methods = ['GET', 'POST']

    def handle(self):
        # Get all necessary objects from backend
        provisioners = self.kqueen_request('provisioner', 'list')
        engines = self.kqueen_request('provisioner', 'engines')
        engine_dict = dict([(e.pop('name'), e) for e in engines])
    
        # Append tagged parameter fields to form
        form_cls = ClusterCreateForm
        for provisioner in provisioners:
            engine = engine_dict.get(provisioner['engine'], {})
            _parameters = engine.get('parameters', {}).get('cluster', {})
            # Append provisioner ID to parameter name to make it unique
            parameters = {
                k + '__' + provisioner['id']: v
                for [k, v]
                in _parameters.items()
            }
            form_cls.append_fields(parameters, switchtag=provisioner['id'])
    
        # Instantiate form and populate provisioner choices
        form = form_cls()
        form.provisioner.choices = [(p['id'], p['name']) for p in provisioners]
    
        if form.validate_on_submit():
            try:
                # Filter out populated tagged fields and get their data
                metadata = {
                    k.split('__')[0]: v.data
                    for (k, v)
                    in form._fields.items()
                    if (hasattr(v, 'switchtag') and v.switchtag) and form.provisioner.data in k
                }
            except Exception as e:
                self.logger('error', repr(e))
                flash('Invalid cluster metadata.', 'danger')
                render_template('ui/cluster_create.html', form=form)
    
            cluster_kw = {
                'name': form.name.data,
                'state': app.config['CLUSTER_PROVISIONING_STATE'],
                'provisioner': 'Provisioner:{}'.format(form.provisioner.data),
                'created_at': datetime.utcnow(),
                'metadata': metadata
            }
            cluster = self.kqueen_request('cluster', 'create', fnargs=(cluster_kw,))
            flash('Provisioning of cluster {} is in progress.'.format(cluster['name']), 'success')
            return redirect('/')
        return render_template('ui/cluster_create.html', form=form)

ui.add_url_rule('/clusters/create', view_func=ClusterCreate.as_view('cluster_create'))


@ui.route('/clusters/<cluster_id>/delete')
@login_required
def cluster_delete(cluster_id):
    try:
        UUID(cluster_id, version=4)
    except ValueError:
        logger.warning('cluster_delete view: invalid uuid {}'.format(str(cluster_id)))
        abort(404)

    try:
        client = get_kqueen_client(token=session['user']['token'])
        _cluster = client.cluster.get(cluster_id)
        cluster = _cluster.data

        if not cluster:
            logger.warning('cluster_delete view: cluster {} not found'.format(str(cluster_id)))
            abort(404)
        if cluster['state'] != app.config['CLUSTER_OK_STATE']:
            flash('Cannot delete cluster {}. Only running clusters can be deleted.'.format(cluster['name']), 'warning')
            return redirect(request.environ['HTTP_REFERER'])

        response = client.cluster.delete(cluster_id)
        if response.status > 200:
            logger.error('cluster_delete view: {}'.format(response.error))
            flash('Cluster {} could not be destroyed.'.format(cluster['name']), 'danger')
        else:
            flash('Cluster {} is being destroyed.'.format(cluster['name']), 'success')
        return redirect(request.environ['HTTP_REFERER'])
    except Exception as e:
        logger.error('cluster_delete view: {}'.format(repr(e)))
        abort(500)


############
# JSON Views
############

@ui.route('/clusters/<cluster_id>/kubeconfig')
@login_required
def cluster_kubeconfig(cluster_id):
    try:
        UUID(cluster_id, version=4)
    except ValueError:
        logger.warning('cluster_kubeconfig view: invalid uuid {}'.format(str(cluster_id)))
        abort(400)

    try:
        client = get_kqueen_client(token=session['user']['token'])
        _cluster = client.cluster.get(cluster_id)
        cluster = _cluster.data
        if not cluster:
            logger.warning('cluster_kubeconfig view: {} not found'.format(str(cluster_id)))
            abort(404)
    except Exception as e:
        logger.error('cluster_kubeconfig view: {}'.format(repr(e)))
        abort(500)

    return jsonify(cluster['kubeconfig'])


@ui.route('/clusters/<cluster_id>/topology-data')
@login_required
def cluster_topology_data(cluster_id):
    try:
        UUID(cluster_id, version=4)
    except ValueError:
        logger.error('cluster_topology_data view: invalid uuid {}'.format(str(cluster_id)))
        abort(400)

    topology = {}
    try:
        client = get_kqueen_client(token=session['user']['token'])
        _topology = client.cluster.topology_data(cluster_id)
        topology = _topology.data
        if not topology:
            logger.warning('cluster_topology_data view: {} not found'.format(str(cluster_id)))
            abort(404)
    except Exception as e:
        logger.error('cluster_topology_data view: {}'.format(repr(e)))
        abort(500)

    return jsonify(topology)


@ui.route('/clusters/<cluster_id>/deployment-status')
@login_required
def cluster_deployment_status(cluster_id):
    try:
        UUID(cluster_id, version=4)
    except ValueError:
        logger.warning('cluster_deployment_status view: invalid uuid {}'.format(str(cluster_id)))
        abort(404)

    dummy = {
        'response': 0,
        'progress': 1,
        'result': 'Deploying'
    }

    return jsonify(dummy)
