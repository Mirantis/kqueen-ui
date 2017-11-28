from datetime import datetime
from flask import (current_app as app, abort, Blueprint, flash, jsonify, redirect,
                   render_template, request, session, url_for)
from flask_mail import Mail, Message
from kqueen_ui.api import get_kqueen_client, get_service_client
from kqueen_ui.auth import authenticate, confirm_token, generate_confirmation_token
from kqueen_ui.utils.wrappers import login_required
from uuid import UUID

from .forms import (ClusterCreateForm, ProvisionerCreateForm, ClusterApplyForm,
                    ChangePasswordForm, UserInviteForm, RequestPasswordResetForm,
                    PasswordResetForm)
from .tables import ClusterTable, OrganizationMembersTable, ProvisionerTable
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
        if response.status == -1:
            flash('Backend is unavailable at this time, please try again later.', 'danger')


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
            if app.config['CLUSTER_ERROR_STATE'] not in cluster['state']:
                healthy_clusters = healthy_clusters + 1

    clustertable = ClusterTable(clusters)

    for provisioner in provisioners:
        provisioner['engine_name'] = prettify_engine_name(provisioner['engine'])
        if 'state' in provisioner:
            if app.config['PROVISIONER_ERROR_STATE'] not in provisioner['state']:
                healthy_provisioners = healthy_provisioners + 1

    provisionertable = ProvisionerTable(provisioners)

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
                           clustertable=clustertable,
                           provisionertable=provisionertable)


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
            member['state'] = 'Active'
            if 'email' not in member:
                member['email'] = '-'
    except Exception as e:
        logger.error('organization_manage view: {}'.format(repr(e)))
        organization = {}
        members = []

    membertable = OrganizationMembersTable(members)
    return render_template('ui/organization_manage.html',
                           organization=organization,
                           membertable=membertable)


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

@ui.route('/users/invite', methods=['GET', 'POST'])
@login_required
def user_invite():
    form = UserInviteForm()
    if form.validate_on_submit():
        organization = 'Organization:{}'.format(session['user']['organization']['id'])
        password = generate_password()
        user = {
            'username': form.email.data,
            'password': password,
            'email': form.email.data,
            'organization': organization,
            'created_at': datetime.utcnow(),
            'active': True
        }
        client = get_kqueen_client(token=session['user']['token'])
        response = client.user.create(user)
        if response.status > 200:
            flash('Could not create user.', 'danger')
            return render_template('ui/user_create.html', form=form)
        user_id = response.data['id']

        # Init mail handler
        mail.init_app(app)
        token = generate_confirmation_token(form.email.data)
        html = render_template(
            'ui/email/user_invitation.html',
            username=form.email.data,
            token=token,
            organization=session['user']['organization']['name']
        )
        msg = Message(
            '[KQueen] Organization invitation',
            recipients=[form.email.data],
            html=html
        )
        try:
            mail.send(msg)
        except Exception as e:
            logger.error('user_create view: {}'.format(repr(e)))
            client.user.delete(user_id)
            flash('Could not send invitation e-mail, please try again later.', 'danger')
            return render_template('ui/user_create.html', form=form)

        flash('User {} successfully created.'.format(user['username']), 'success')
        return redirect(url_for('ui.organization_manage'))
    return render_template('ui/user_create.html', form=form)


@ui.route('/users/<user_id>/delete')
@login_required
def user_delete(user_id):
    try:
        UUID(user_id, version=4)
    except ValueError:
        logger.warning('user_delete view: invalid uuid {}'.format(str(user_id)))
        abort(404)

    try:
        client = get_kqueen_client(token=session['user']['token'])
        _user = client.user.get(user_id)
        user = _user.data
        if not user:
            logger.warning('user_delete view: user {} not found'.format(str(user_id)))
            abort(404)
        client.user.delete(user_id)
        flash('User {} successfully deleted.'.format(user['username']), 'success')
        return redirect(request.environ['HTTP_REFERER'])
    except Exception as e:
        logger.error('user_delete view: {}'.format(repr(e)))
        abort(500)


@ui.route('/users/changepw', methods=['GET', 'POST'])
@login_required
def user_change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        try:
            client = get_kqueen_client(token=session['user']['token'])
            _user = client.user.get(session['user']['id'])
            if _user.status == 200:
                user = _user.data
                user['password'] = form.password_1.data
                update = client.user.update(user['id'], user)
                if update.status == 200:
                    flash('Password successfully updated. Please log in again.', 'success')
                    return redirect(url_for('ui.logout'))
            flash('Could not change password. Please try again later.', 'danger')
        except Exception as e:
            logger.error('user_change_password view: {}'.format(repr(e)))
            flash('Password update failed.', 'danger')
    return render_template('ui/user_change_password.html', form=form)


@ui.route('/users/resetpw/<token>', methods=['GET', 'POST'])
def user_password_reset(token):
    email = confirm_token(token)
    if not email:
        flash('Password reset link is invalid or has expired.', 'danger')
        return redirect(url_for('ui.index'))

    client = get_service_client()
    _users = client.user.list()
    users = _users.data

    # TODO: this logic realies heavily on unique emails, this is not the case on backend right now
    filtered = [u for u in users if u.get('email', None) == email]
    if len(filtered) == 1:
        user = filtered[0]
        form = PasswordResetForm()
        if form.validate_on_submit():
            try:
                user['password'] = form.password_1.data
                update = client.user.update(user['id'], user)
                if update.status == 200:
                    flash('Password successfully updated. Please log in again.', 'success')
                    return redirect(url_for('ui.login'))
                flash('Could not change password. Please try again later.', 'danger')
            except Exception as e:
                logger.error('user_password_reset view: {}'.format(repr(e)))
                flash('Could not change password. Please try again later.', 'danger')
        return render_template('ui/user_reset_password.html', form=form)
    else:
        flash('No user found based on given e-mail.', 'danger')
    return redirect(url_for('ui.index'))


@ui.route('/users/requestresetpw', methods=['GET', 'POST'])
def user_request_password_reset():
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
            logger.error('request_password_reset view: {}'.format(repr(e)))
            flash('Could not send password reset e-mail, please try again later.', 'danger')
        flash('Password reset link was sent to your e-mail address.', 'success')
        return redirect(url_for('ui.index'))
    return render_template('ui/user_request_password_reset.html', form=form)


# Provisioner

@ui.route('/provisioners/create', methods=['GET', 'POST'])
@login_required
def provisioner_create():
    # Get engines with parameters
    client = get_kqueen_client(token=session['user']['token'])
    _engines = client.provisioner.engines()
    engines = _engines.data

    # Append tagged parameter fields to form
    form_cls = ProvisionerCreateForm
    for engine in engines:
        form_cls.append_fields(engine['parameters']['provisioner'], switchtag=engine['name'])

    # Instantiate form and populate engine choices
    form = form_cls()
    form.engine.choices = [(e['name'], prettify_engine_name(e['name'])) for e in engines]

    if form.validate_on_submit():
        try:
            # Filter out populated tagged fields and get their data
            parameters = {
                k: v.data
                for (k, v)
                in form._fields.items()
                if (hasattr(v, 'switchtag') and v.switchtag) and v.data
            }
            provisioner = {
                'name': form.name.data,
                'engine': form.engine.data,
                'state': app.config['PROVISIONER_UNKNOWN_STATE'],
                'parameters': parameters,
                'created_at': datetime.utcnow()
            }
            client.provisioner.create(provisioner)
            flash('Provisioner {} successfully created.'.format(provisioner['name']), 'success')
        except Exception as e:
            logger.error('provisioner_create view: {}'.format(repr(e)))
            flash('Could not create provisioner.', 'danger')
        return redirect('/')
    return render_template('ui/provisioner_create.html', form=form)


@ui.route('/provisioners/<provisioner_id>/delete')
@login_required
def provisioner_delete(provisioner_id):
    try:
        UUID(provisioner_id, version=4)
    except ValueError:
        logger.warning('provisioner_delete view: invalid uuid {}'.format(str(provisioner_id)))
        abort(404)

    try:
        # TODO: block deletion of used provisioner on backend, not here
        client = get_kqueen_client(token=session['user']['token'])
        _clusters = client.cluster.list()
        clusters = _clusters.data
        _provisioner = client.provisioner.get(provisioner_id)
        provisioner = _provisioner.data
        if not provisioner:
            logger.warning('provisioner_delete view: {} not found'.format(str(provisioner_id)))
            abort(404)
        used_provisioners = [p['id'] for p in [c['provisioner'] for c in clusters]]

        if provisioner_id not in used_provisioners:
            client.provisioner.delete(provisioner_id)
            flash('Provisioner {} successfully deleted.'.format(provisioner['name']), 'success')
        else:
            flash('Provisioner {} is used by deployed cluster, cannot delete.'.format(provisioner['name']), 'warning')

        return redirect('/')
    except Exception as e:
        logger.error('provisioner_delete view: {}'.format(repr(e)))
        abort(500)


# Cluster

@ui.route('/clusters/deploy', methods=['GET', 'POST'])
@login_required
def cluster_create():
    # Get all necessary objects from backend
    client = get_kqueen_client(token=session['user']['token'])
    _provisioners = client.provisioner.list()
    provisioners = _provisioners.data
    _engines = client.provisioner.engines()
    engines = _engines.data
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

    if request.method == 'POST':
        if form.validate_on_submit():
            try:
                # Filter out populated tagged fields and get their data
                metadata = {
                    k.split('__')[0]: v.data
                    for (k, v)
                    in form._fields.items()
                    if (hasattr(v, 'switchtag') and v.switchtag) and form.provisioner.data in k
                }

                cluster = {
                    'name': form.name.data,
                    'state': app.config['CLUSTER_PROVISIONING_STATE'],
                    'provisioner': 'Provisioner:{}'.format(form.provisioner.data),
                    'created_at': datetime.utcnow(),
                    'metadata': metadata
                }
                response = client.cluster.create(cluster)
                if response.status > 200:
                    flash('Could not create cluster {}.'.format(form.name.data), 'danger')
                flash('Provisioning of cluster {} is in progress.'.format(form.name.data), 'success')
            except Exception as e:
                logger.error('cluster_create view: {}'.format(repr(e)))
                flash('Could not create cluster {}.'.format(form.name.data), 'danger')
            return redirect('/')
    return render_template('ui/cluster_create.html', form=form)


@ui.route('/clusters/<cluster_id>/delete')
@login_required
def cluster_delete(cluster_id):
    # TODO: actually deprovision cluster
    return redirect('/')


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
