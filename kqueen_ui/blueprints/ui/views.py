from .forms import (ClusterCreateForm, ProvisionerCreateForm, ClusterApplyForm,
                    ChangePasswordForm, UserCreateForm)
from .tables import ClusterTable, OrganizationMembersTable, ProvisionerTable
from .utils import status_for_cluster_detail
from flask import (current_app as app, abort, Blueprint, flash, jsonify, redirect,
                   render_template, request, session, url_for)
from kqueen_ui.api import KQueenAPIClient
from kqueen_ui.auth import authenticate
from kqueen_ui.wrappers import login_required
from uuid import UUID

import yaml
import logging
import sys

logger = logging.getLogger(__name__)

ui = Blueprint('ui', __name__, template_folder='templates')


# logins
@ui.route('/')
@login_required
def index():
    clusters = []
    healthy_clusters = 0
    provisioners = []
    healthy_provisioners = 0

    if session.get('token', None):
        client = KQueenAPIClient(token=session['token'])
        clusters = client.cluster.list()
        provisioners = client.provisioner.list()

    for cluster in clusters:
        if 'state' in cluster:
            if app.config['CLUSTER_ERROR_STATE'] not in cluster['state']:
                healthy_clusters = healthy_clusters + 1

    clustertable = ClusterTable(clusters)

    for provisioner in provisioners:
        if 'state' in provisioner:
            if app.config['PROVISIONER_ERROR_STATE'] not in provisioner['state']:
                healthy_provisioners = healthy_provisioners + 1

    provisionertable = ProvisionerTable(provisioners)

    overview = {
        'cluster_health': int((healthy_clusters / len(clusters)) * 100) if (healthy_clusters and clusters) else 100,
        'provisioner_health': int((healthy_provisioners / len(provisioners)) * 100) if (healthy_provisioners and provisioners) else 100,
    }
    return render_template('ui/index.html', overview=overview, clustertable=clustertable, provisionertable=provisionertable)


@ui.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        user, token = authenticate(request.form['username'], request.form['password'])
        if user and token:
            session['user_id'] = user['id']
            session['organization_id'] = user['organization']
            session['token'] = token
            flash('You were logged in', 'success')
            next_url = request.form.get('next', '')
            if next_url:
                return redirect(next_url)
            return redirect(url_for('.index'))
        else:
            error = 'Invalid credentials'

    return render_template('ui/login.html', error=error)


@ui.route('/logout')
@login_required
def logout():
    del session['user_id']
    del session['organization_id']
    del session['token']
    flash('You were logged out', 'success')
    return redirect(url_for('.index'))


@ui.route('/users/changepw', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        try:
            #user = User.load(session['user_id'])
            #user.password = form.password_1.data
            #user.save()
            flash('Password successfully updated. Please log in again.', 'success')
            return redirect(url_for('ui.logout'))
        except Exception as e:
            logger.error('Could not update password: {}'.format(repr(e)))
            flash('Password update failed.', 'danger')
    return render_template('ui/change_password.html', form=form)


@ui.route('/users/create', methods=['GET', 'POST'])
@login_required
def user_create():
    form = UserCreateForm()
    if form.validate_on_submit():
        try:
            # Instantiate new user DB object
            #user = User(
            #    username=form.username.data,
            #    password=form.password_1.data,
            #    email=form.email.data or None,
            #    organization=session['organization_id']
            #)
            #user.save()
            flash('User {} successfully created.'.format(user.username), 'success')
        except Exception as e:
            logger.error('Could not create user: {}'.format(repr(e)))
            flash('Could not create user.', 'danger')
        return redirect(url_for('ui.organization_manage'))
    return render_template('ui/user_create.html', form=form)


@ui.route('/users/<user_id>/delete')
@login_required
def user_delete(user_id):
    try:
        object_id = UUID(user_id, version=4)
    except ValueError:
        abort(404)

    # load object
    try:
        #obj = User.load(object_id)
        #obj.delete()
        flash('User {} successfully deleted.'.format(obj.username), 'success')
        return redirect(request.environ['HTTP_REFERER'])
    except NameError:
        abort(404)
    except Exception as e:
        logger.error(e)
        abort(500)


@ui.route('/organizations/manage')
@login_required
def organization_manage():
    try:
        # TODO: teach ORM to get related objects for us
        client = KQueenAPIClient(token=session['token'])
        organization = client.organization.get(session['organization_id'])
        users = client.user.list()
        members = [
            u
            for u
            in users
            if u['organization'] == session['organization_id'] and u['id'] != session['user_id']
        ]
        # Patch members until we actually have these data for realsies
        for member in members:
            member['role'] = 'Member'
            member['state'] = 'Active'
            if 'email' not in member:
                member['email'] = '-'
    except:
        organization = {}
        members = []
    membertable = OrganizationMembersTable(members)
    return render_template('ui/organization_manage.html',
                           organization=organization,
                           membertable=membertable)


# catalog
@ui.route('/catalog')
@login_required
def catalog():
    return render_template('ui/catalog.html')


# provisioner
@ui.route('/provisioners/create', methods=['GET', 'POST'])
@login_required
def provisioner_create():
    form = ProvisionerCreateForm()
    if form.validate_on_submit():
        try:
            # Instantiate new provisioner DB object
            #provisioner = Provisioner(
            #    name=form.name.data,
            #    engine=form.engine.data,
            #    state=app.config['PROVISIONER_UNKNOWN_STATE'],
            #    parameters={
            #        'username': form.username.data,
            #        'password': form.password.data
            #    }
            #)
            #provisioner.save()
            flash('Provisioner {} successfully created.'.format(provisioner.name), 'success')
        except Exception as e:
            logger.error('Could not create provisioner: {}'.format(repr(e)))
            flash('Could not create provisioner.', 'danger')
        return redirect('/')
    return render_template('ui/provisioner_create.html', form=form)


@ui.route('/provisioners/<provisioner_id>/delete')
@login_required
def provisioner_delete(provisioner_id):
    try:
        object_id = UUID(provisioner_id, version=4)
    except ValueError:
        abort(404)

    # load object
    try:
        #used_provisioners = [c.provisioner for c in list(Cluster.list(return_objects=True).values())]
        #obj = Provisioner.load(object_id)
        #if str(object_id) not in used_provisioners:
        #    obj.delete()
        #    flash('Provisioner {} successfully deleted.'.format(obj.name), 'success')
        #else:
        #    flash('Provisioner {} is used by deployed cluster, cannot delete.'.format(obj.name), 'warning')
        flash('Provisioner {} successfully deleted.'.format(obj.name), 'success')
        return redirect('/')
    except NameError:
        abort(404)
    except Exception as e:
        logger.error(e)
        abort(500)


# cluster
@ui.route('/clusters/deploy', methods=['GET', 'POST'])
@login_required
def cluster_deploy():
    form = ClusterCreateForm()
    client = KQueenAPIClient(token=session['token'])
    form.provisioner.choices = [(p['id'], p['name']) for p in client.provisioner.list()]

    if request.method == 'POST':
        if form.validate_on_submit():
            # Create cluster object
            try:
                # load kubeconfig
                kubeconfig = {}
                kubeconfig_file = form.kubeconfig.data

                if kubeconfig_file:
                    try:
                        kubeconfig = yaml.load(kubeconfig_file.stream)
                    except:
                        logger.error(sys.exc_info())

                #cluster = Cluster(
                #    name=form.name.data,
                #    state=app.config['CLUSTER_PROVISIONING_STATE'],
                #    provisioner=form.provisioner.data,
                #    kubeconfig=kubeconfig,
                #)

                #cluster.save()
            except Exception as e:
                flash('Could not create cluster {}.'.format(form.name.data), 'danger')
                logger.error('Creating cluster {} failed with following reason: {}'.format(form.name.data, repr(e)))

                return redirect('/')

            # Actually provision cluster
            result = False

            #try:
            #    result, err = cluster.engine.provision()
            #except Exception as e:
            #    flash('Provisioning failed for {}.'.format(form.name.data), 'danger')
            #    logger.error('Provisioning cluster {} failed with following reason: {}'.format(form.name.data, repr(e)))
            #    return redirect('/')

            if result:
                flash('Provisioning of cluster {} is in progress.'.format(form.name.data), 'success')
            else:
                logger.error('Creating cluster {} failed with following reason: {}'.format(form.name.data, str(err)))
                flash('Could not create cluster {}: {}.'.format(form.name.data, err), 'danger')

            return redirect('/')

    return render_template('ui/cluster_deploy.html', form=form)


@ui.route('/clusters/<cluster_id>/detail', methods=['GET', 'POST'])
@login_required
def cluster_detail(cluster_id):
    try:
        object_id = UUID(cluster_id, version=4)
    except ValueError:
        abort(404)

    # load object
    #try:
    #    obj = Cluster.load(object_id)
    #    obj.get_state()
    #except NameError:
    #    abort(404)

    # load information about clusters
    client = KQueenAPIClient(token=session['token'])

    cluster_dict = client.cluster.get(cluster_id)

    _status = {}
    state_class = 'info'
    state = cluster_dict['state']
    if state == app.config['CLUSTER_OK_STATE']:
        state_class = 'success'
        try:
            _status = client.cluster.status(cluster_id)
        except:
            flash('Unable to get information about cluster', 'danger')
    elif state == app.config['CLUSTER_ERROR_STATE']:
        state_class = 'danger'

    status = status_for_cluster_detail(_status)

    form = ClusterApplyForm()
    if form.validate_on_submit():
        #obj.apply(form.apply.data)
        pass

    return render_template(
        'ui/cluster_detail.html',
        cluster=cluster_dict,
        status=status,
        state_class=state_class,
        form=form
    )


@ui.route('/clusters/<cluster_id>/kubeconfig')
@login_required
def cluster_kubeconfig(cluster_id):

    try:
        object_id = UUID(cluster_id, version=4)
    except ValueError:
        abort(400)

    # load object
    try:
        client = KQueenAPIClient(token=session['token'])
        cluster = client.cluster.get(cluster_id)
    except NameError:
        abort(404)

    return jsonify(cluster['kubeconfig'])


@ui.route('/clusters/<cluster_id>/topology-data')
@login_required
def cluster_topology_data(cluster_id):

    try:
        object_id = UUID(cluster_id, version=4)
    except ValueError:
        abort(400)

    # load object
    topology = {}
    try:
        client = KQueenAPIClient(token=session['token'])
        topology = client.cluster.topology_data(cluster_id)
    except NameError:
        abort(404)

    return jsonify(topology)


@ui.route('/clusters/<cluster_id>/delete')
@login_required
def cluster_delete(cluster_id):
    # TODO: actually deprovision cluster
    return redirect('/')


@ui.route('/clusters/<cluster_id>/deployment-status')
@login_required
def cluster_deployment_status(cluster_id):
    try:
        object_id = UUID(cluster_id, version=4)
    except ValueError:
        logger.debug('{] not valid UUID'.format(cluster_id))
        abort(404)

    # load object
    # cluster = Cluster.load(object_id)
    # status = cluster.engine.get_progress()

    return jsonify({})
