from datetime import datetime
from flask import (current_app as app, Blueprint, flash, jsonify, redirect,
                   render_template, request, session, url_for)
from flask_babel import format_datetime
from flask_mail import Mail, Message
from kqueen_ui.api import get_kqueen_client
from kqueen_ui.auth import authenticate, confirm_token, generate_confirmation_token
from kqueen_ui.generic_views import KQueenView
from kqueen_ui.utils.wrappers import login_required

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

# Index

class Index(KQueenView):
    decorators = [login_required]
    methods = ['GET']

    def handle(self):
        clusters = self.kqueen_request('cluster', 'list')
        provisioners = self.kqueen_request('provisioner', 'list')
        deployed_clusters = 0
        healthy_clusters = 0
        healthy_provisioners = 0

        # sort clusters by date
        if isinstance(clusters, list):
            clusters.sort(key=lambda k: (k['created_at'], k['name']))

        for cluster in clusters:
            if 'state' in cluster:
                if app.config['CLUSTER_PROVISIONING_STATE'] != cluster['state']:
                    deployed_clusters = deployed_clusters + 1
                if cluster['state'] in [app.config['CLUSTER_RESIZING_STATE'], app.config['CLUSTER_OK_STATE']]:
                    healthy_clusters = healthy_clusters + 1
            if 'created_at' in cluster:
                cluster['created_at'] = format_datetime(cluster['created_at'])

        # sort provisioners by date
        if isinstance(provisioners, list):
            provisioners.sort(key=lambda k: (k['created_at'], k['name']))

        for provisioner in provisioners:
            if 'state' in provisioner:
                if app.config['PROVISIONER_ERROR_STATE'] != provisioner['state']:
                    healthy_provisioners = healthy_provisioners + 1
            if 'created_at' in provisioner:
                provisioner['created_at'] = format_datetime(provisioner['created_at'])

        cluster_health = 0
        if healthy_clusters and deployed_clusters:
            cluster_health = int((healthy_clusters / deployed_clusters) * 100)
        provisioner_health = 0
        if healthy_provisioners and provisioners:
            provisioner_health = int((healthy_provisioners / len(provisioners)) * 100)

        overview = {
            'cluster_count': len(clusters),
            'cluster_max': len(clusters) if len(clusters) else 1,
            'cluster_health': cluster_health,
            'provisioner_count': len(provisioners),
            'provisioner_max': len(provisioners) if len(provisioners) else 1,
            'provisioner_health': provisioner_health,
        }
        return render_template('ui/index.html',
                               overview=overview,
                               clusters=clusters,
                               provisioners=provisioners)


ui.add_url_rule('/', view_func=Index.as_view('index'))


# Auth

@ui.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        user, _error = authenticate(request.form['username'], request.form['password'])
        if user:
            session['user'] = user
            client = get_kqueen_client(token=user['token'])
            organization_id = user['organization']['id']
            response = client.organization.policy(organization_id)
            if response.status == -1:
                flash('Backend is unavailable at this time, please try again later.', 'danger')
                del session['user']
                if 'policy' in session:
                    del session['policy']
                return render_template('ui/login.html', error=error)
            elif response.status > 200:
                flash('Could not contact authentication backend, please try again later.', 'danger')
                del session['user']
                if 'policy' in session:
                    del session['policy']
                return render_template('ui/login.html', error=error)
            policy = response.data
            if policy and isinstance(policy, dict):
                session['policy'] = policy
            else:
                del session['user']
                if 'policy' in session:
                    del session['policy']
                return render_template('ui/login.html', error=error)

            flash('You have been logged in', 'success')
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
    if 'policy' in session:
        del session['policy']
    flash('You have been logged out', 'success')
    return redirect(url_for('ui.index'))


################
# Resource Views
################

#
# Organization
#

class OrganizationManage(KQueenView):
    decorators = [login_required]
    methods = ['GET']

    def handle(self):
        # session data
        organization_id = session['user']['organization']['id']
        user_id = session['user']['id']
        # backend resources
        organization = self.kqueen_request('organization', 'get', fnargs=(organization_id,))
        users = self.kqueen_request('user', 'list')
        members = [
            u
            for u
            in users
            if u['organization']['id'] == organization_id and u['id'] != user_id
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

        return render_template('ui/organization_manage.html',
                               organization=organization,
                               members=members)


ui.add_url_rule('/organizations/manage', view_func=OrganizationManage.as_view('organization_manage'))


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
                'role': 'member',
                'created_at': datetime.utcnow(),
                'active': False
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


class UserReinvite(KQueenView):
    decorators = [login_required]
    methods = ['GET']
    validation_hint = 'uuid'

    def handle(self, user_id):
        user = self.kqueen_request('user', 'get', fnargs=(user_id,))
        if user['active']:
            flash('User {} is already active.'.format(user['username']), 'warning')
            return redirect(request.environ.get('HTTP_REFERER', url_for('ui.organization_manage')))

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
            flash('Could not send activation e-mail, please try again later.', 'danger')
            return redirect(request.environ.get('HTTP_REFERER', url_for('ui.organization_manage')))

        flash('Activation e-mail sent to user {}.'.format(user['username']), 'success')
        return redirect(request.environ.get('HTTP_REFERER', url_for('ui.organization_manage')))


class UserDelete(KQueenView):
    decorators = [login_required]
    methods = ['GET']
    validation_hint = 'uuid'

    def handle(self, user_id):
        user = self.kqueen_request('user', 'get', fnargs=(user_id,))
        self.kqueen_request('user', 'delete', fnargs=(user_id,))
        flash('User {} successfully deleted.'.format(user['username']), 'success')
        return redirect(request.environ.get('HTTP_REFERER', url_for('ui.index')))


class UserChangePassword(KQueenView):
    decorators = [login_required]
    methods = ['GET', 'POST']

    def handle(self):
        form = ChangePasswordForm()
        if form.validate_on_submit():
            user_id = session['user']['id']
            password = {'password': form.password_1.data}
            self.kqueen_request('user', 'updatepw', fnargs=(user_id, password))
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
                password = {'password': form.password_1.data}
                self.kqueen_request('user', 'updatepw', fnargs=(user['id'], password), service=True)
                flash('Password successfully updated.', 'success')
                return redirect(url_for('ui.login'))
            return render_template('ui/user_reset_password.html', form=form)
        else:
            flash('Could not match user to given e-mail.', 'danger')
        return redirect(url_for('ui.index'))


class UserSetPassword(KQueenView):
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
                password = {'password': form.password_1.data}
                self.kqueen_request('user', 'updatepw', fnargs=(user['id'], password), service=True)
                user['active'] = True
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
ui.add_url_rule('/users/<user_id>/reinvite', view_func=UserReinvite.as_view('user_reinvite'))
ui.add_url_rule('/users/<user_id>/delete', view_func=UserDelete.as_view('user_delete'))
ui.add_url_rule('/users/changepw', view_func=UserChangePassword.as_view('user_change_password'))
ui.add_url_rule('/users/resetpw/<token>', view_func=UserResetPassword.as_view('user_reset_password'))
ui.add_url_rule('/users/setpw/<token>', view_func=UserSetPassword.as_view('user_set_password'))
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
        form.engine.choices = [(e['name'], e['verbose_name']) for e in engines]

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

            owner_ref = 'User:{}'.format(session['user']['id'])
            provisioner_kw = {
                'name': form.name.data,
                'engine': form.engine.data,
                'state': app.config['PROVISIONER_UNKNOWN_STATE'],
                'parameters': parameters,
                'created_at': datetime.utcnow(),
                'owner': owner_ref
            }
            provisioner = self.kqueen_request('provisioner', 'create', fnargs=(provisioner_kw,))
            flash('Provisioner {} successfully created.'.format(provisioner['name']), 'success')
            return redirect(url_for('ui.index'))
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

        return redirect(request.environ.get('HTTP_REFERER', url_for('ui.index')))


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

            owner_ref = 'User:{}'.format(session['user']['id'])
            cluster_kw = {
                'name': form.name.data,
                'state': app.config['CLUSTER_PROVISIONING_STATE'],
                'provisioner': 'Provisioner:{}'.format(form.provisioner.data),
                'created_at': datetime.utcnow(),
                'metadata': metadata,
                'owner': owner_ref
            }
            cluster = self.kqueen_request('cluster', 'create', fnargs=(cluster_kw,))
            flash('Provisioning of cluster {} is in progress.'.format(cluster['name']), 'success')
            return redirect(url_for('ui.index'))
        return render_template('ui/cluster_create.html', form=form)


class ClusterDelete(KQueenView):
    decorators = [login_required]
    methods = ['GET']
    validation_hint = 'uuid'

    def handle(self, cluster_id):
        cluster = self.kqueen_request('cluster', 'get', fnargs=(cluster_id,))
        if cluster['state'] == app.config['CLUSTER_PROVISIONING_STATE']:
            # TODO: handle state together with policies in helper for allowed table actions
            flash('Cannot delete clusters during provisioning.', 'warning')
            return redirect(request.environ.get('HTTP_REFERER', url_for('ui.index')))
        self.kqueen_request('cluster', 'delete', fnargs=(cluster_id,))
        flash('Cluster {} successfully deleted.'.format(cluster['name']), 'success')
        return redirect(request.environ.get('HTTP_REFERER', url_for('ui.index')))


class ClusterDeploymentStatus(KQueenView):
    decorators = [login_required]
    methods = ['GET']
    validation_hint = 'uuid'

    def handle(self, cluster_id):
        progress = self.kqueen_request('cluster', 'progress', fnargs=(cluster_id,))
        return jsonify(progress)


class ClusterDetail(KQueenView):
    decorators = [login_required]
    methods = ['GET', 'POST']
    validation_hint = 'uuid'

    def handle(self, cluster_id):
        cluster = self.kqueen_request('cluster', 'get', fnargs=(cluster_id,))
        state_class = 'info'
        _status_data = {}

        if cluster['state'] == app.config['CLUSTER_OK_STATE']:
            state_class = 'success'
            _status_data = self.kqueen_request('cluster', 'status', fnargs=(cluster_id,))
        elif cluster['state'] == app.config['CLUSTER_ERROR_STATE']:
            state_class = 'danger'
        elif cluster['state'] == app.config['CLUSTER_UNKNOWN_STATE']:
            state_class = 'warning'

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


class ClusterResize(KQueenView):
    decorators = [login_required]
    methods = ['POST']
    validation_hint = 'uuid'

    def handle(self, cluster_id):
        cluster = self.kqueen_request('cluster', 'get', fnargs=(cluster_id,))
        if 'node_count' not in cluster.get('metadata', {}):
            flash("This cluster doesn't support scaling.", 'warning')
            return redirect(request.environ.get('HTTP_REFERER', url_for('ui.index')))
        current_node_count = cluster['metadata']['node_count']
        node_count = request.form['node_count']
        if current_node_count == node_count:
            return redirect(request.environ.get('HTTP_REFERER', url_for('ui.index')))
        self.kqueen_request('cluster', 'resize', fnargs=(cluster_id, node_count))
        return redirect(request.environ.get('HTTP_REFERER', url_for('ui.index')))


class ClusterKubeconfig(KQueenView):
    decorators = [login_required]
    methods = ['GET']
    validation_hint = 'uuid'

    def handle(self, cluster_id):
        cluster = self.kqueen_request('cluster', 'get', fnargs=(cluster_id,))
        return jsonify(cluster['kubeconfig'])


class ClusterTopologyData(KQueenView):
    decorators = [login_required]
    methods = ['GET']
    validation_hint = 'uuid'

    def handle(self, cluster_id):
        topology = self.kqueen_request('cluster', 'topology_data', fnargs=(cluster_id,))
        return jsonify(topology)


ui.add_url_rule('/clusters/create', view_func=ClusterCreate.as_view('cluster_create'))
ui.add_url_rule('/clusters/<cluster_id>/delete', view_func=ClusterDelete.as_view('cluster_delete'))
ui.add_url_rule('/clusters/<cluster_id>/deployment-status', view_func=ClusterDeploymentStatus.as_view('cluster_deployment_status'))
ui.add_url_rule('/clusters/<cluster_id>/detail', view_func=ClusterDetail.as_view('cluster_detail'))
ui.add_url_rule('/clusters/<cluster_id>/resize', view_func=ClusterResize.as_view('cluster_resize'))
ui.add_url_rule('/clusters/<cluster_id>/kubeconfig', view_func=ClusterKubeconfig.as_view('cluster_kubeconfig'))
ui.add_url_rule('/clusters/<cluster_id>/topology-data', view_func=ClusterTopologyData.as_view('cluster_topology_data'))
