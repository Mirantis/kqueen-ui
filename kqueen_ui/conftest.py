from datetime import datetime
from flask import url_for
from flask_babel import Babel
from flask_cache import Cache
from kqueen_ui import auth
from kqueen_ui.api import KQueenResponse
from kqueen_ui.server import create_app
from uuid import uuid4

import json
import pytest

config_file = 'config/test.py'
cluster_uuid = '1868f6f4-1dbb-4555-ba46-1d2924e81f5e'
organization_uuid = '93d66558-7ed1-4ccd-a1d6-2f903ceb7d7b'
provisioner_uuid = '7ebef38d-a7b6-4c34-bbb0-8c98e820133c'
user_uuid = '59142471-8334-45e4-b632-653692f0523c'
admin_uuid = '59142471-8334-45e4-b632-653692f0523d'
member_uuid = '59142471-8334-45e4-b632-653692f0523e'
superadmin_uuid = '59142471-8334-45e4-b632-653692f0523f'


@pytest.fixture
def app():
    app = create_app(config_file=config_file)
    app.testing = True
    Babel(app)
    Cache(app, config=app.config['CACHE'])
    return app


@pytest.fixture
def organization():
    organization = {
        'id': organization_uuid,
        'name': 'PytestOrg',
        'namespace': 'pytestorg',
        'policy': {},
        'created_at': datetime.utcnow()
    }
    return organization


@pytest.fixture
def default_policy():
    policy = {
        "cluster:create": "ALL",
        "cluster:delete": "ADMIN_OR_OWNER",
        "cluster:get": "ALL",
        "cluster:list": "ALL",
        "cluster:update": "ADMIN_OR_OWNER",
        "organization:create": "IS_SUPERADMIN",
        "organization:delete": "IS_SUPERADMIN",
        "organization:get": "ALL",
        "organization:list": "ALL",
        "organization:update": "IS_SUPERADMIN",
        "provisioner:create": "ALL",
        "provisioner:delete": "ADMIN_OR_OWNER",
        "provisioner:get": "ALL",
        "provisioner:list": "ALL",
        "provisioner:update": "ALL",
        "user:create": "IS_ADMIN",
        "user:delete_member": "IS_ADMIN",
        "user:delete_admin": "IS_ADMIN",
        "user:delete_superadmin": "IS_SUPERADMIN",
        "user:get": "ALL",
        "user:list": "ALL",
        "user:update": "ADMIN_OR_OWNER"
    }
    return policy


@pytest.fixture
def user():
    user = {
        'id': user_uuid,
        'username': 'pytest',
        'password': 'pytest',
        'email': 'pytest@python.org',
        'organization': organization(),
        'active': True,
        'created_at': datetime.utcnow(),
        'role': 'admin',
        'metadata': {},
        'token': token()
    }
    return user


@pytest.fixture
def admin():
    admin = user()
    admin['id'] = admin_uuid
    return admin


@pytest.fixture
def member():
    member = user()
    member['id'] = member_uuid
    member['role'] = 'member'
    return member


@pytest.fixture
def superadmin():
    superadmin = user()
    superadmin['id'] = superadmin_uuid
    superadmin['role'] = 'superadmin'
    return superadmin


@pytest.fixture
def provisioner():
    provisioner = {
        'id': provisioner_uuid,
        'name': 'pytest-provisioner',
        'engine': 'kqueen.engines.JenkinsEngine',
        'state': 'OK',
        'parameters': {
            'username': 'pytest',
            'password': 'pytest'
        },
        'created_at': datetime.utcnow(),
        'owner': user()
    }
    return provisioner


@pytest.fixture
def kubeconfig():
    kubeconfig = {
        'apiVersion': 'v1',
        'clusters': [
            {
                'cluster': {
                    'server': 'http://127.0.0.1:8080'
                },
                'name': 'local'
            }
        ],
        'contexts': [
            {
                'context': {
                    'cluster': 'local',
                    'user': ''
                },
                'name': 'local'
            }
        ],
        'current-context': 'local',
        'kind': 'Config',
        'preferences': {}
    }
    return kubeconfig


@pytest.fixture
def cluster_progress():
    progress = {
        'response': 200,
        'progress': 10,
        'result': 'Deploying'
    }
    return progress


@pytest.fixture
def cluster():
    cluster = {
        'id': cluster_uuid,
        'name': 'pytest-cluster',
        'provisioner': provisioner(),
        'state': 'OK',
        'kubeconfig': kubeconfig(),
        'metadata': {
            'node_count': '2'
        },
        'created_at': datetime.utcnow(),
        'owner': user()
    }
    return cluster


@pytest.fixture
def cluster_status():
    with open('kqueen_ui/fixtures/test_cluster_status.json', 'r') as stream:
        data_loaded = json.load(stream)

    return data_loaded


@pytest.fixture
def auth_configuration():
    with open('kqueen_ui/fixtures/test_auth_configuration.json', 'r') as stream:
        data_loaded = json.load(stream)
    return data_loaded


@pytest.fixture
def provisioner_engines():
    with open('kqueen_ui/fixtures/test_provisioner_engines.json', 'r') as stream:
        data_loaded = json.load(stream)

    return data_loaded


@pytest.fixture
def token():
    return 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE1MDg4NTkwNzksIm5iZiI6MTUwODg1NTQ3OSwiaWRlbnRpdHkiOiIzNmIzMDBmMS0yZDNmLTQ2NzAtOTI4NS0wNTEyOGYzYjM5NmIiLCJpYXQiOjE1MDg4NTU0Nzl9.wGx5bXq5Xmf3lZSXt38BGf4wTg115qxM5Blze4ZYAj0'


@pytest.fixture
def email_token():
    _user = user()
    return auth.generate_confirmation_token(_user['email'])


@pytest.fixture
def client_login(client, monkeypatch):
    def mock_authenticate(username, password):
        return (user(), None)
    monkeypatch.setattr('kqueen_ui.blueprints.ui.views.authenticate', mock_authenticate)
    _user = user()
    client.post(url_for('ui.login'), data={
        'username': _user['username'],
        'password': _user['password']
    })
    return client


@pytest.fixture
def client_login_superadmin(client, monkeypatch):
    def mock_authenticate(username, password):
        return (superadmin(), None)
    monkeypatch.setattr('kqueen_ui.blueprints.ui.views.authenticate', mock_authenticate)
    _user = superadmin()
    client.post(url_for('ui.login'), data={
        'username': _user['username'],
        'password': _user['password']
    })
    return client


@pytest.fixture(autouse=True)
def no_kqueen_requests(monkeypatch):
    def mock_kqueen_request(self, resource, action, fnargs=(), fnkwargs={}, service=False):
        if resource == 'cluster':
            obj = cluster()
        elif resource == 'provisioner':
            obj = provisioner()
        elif resource == 'organization':
            obj = organization()
        elif resource == 'user':
            obj = user()
        elif resource == 'configuration':
            obj = auth_configuration()
        else:
            raise NotImplementedError('Resource {} is not supported by mock_kqueen_request'.format(resource))

        if fnkwargs.get('all_namespaces', True):
            obj['_namespace'] = 'pytestorg'

        if action == 'get':
            return obj
        elif action == 'list':
            return [obj]
        elif action == 'create':
            obj.update(fnkwargs.get('payload', {}))
            # patch object references
            if 'cluster' in obj:
                obj['cluster'] = cluster()
            if 'provisioner' in obj:
                obj['provisioner'] = provisioner()
            if 'organization' in obj:
                obj['organization'] = organization()
            if 'user' in obj:
                obj['user'] = user()
            obj['id'] = uuid4()
            return obj
        elif action == 'delete':
            return {'id': obj['id'], 'state': 'deleted'}
        elif action == 'engines':
            return provisioner_engines()
        elif action == 'status':
            return cluster_status()
        elif action == 'topology_data':
            return {}
        elif action == 'policy':
            return default_policy()
        elif action == 'progress':
            return cluster_progress()
        elif action == 'resize':
            return obj
        elif action == 'update':
            obj.update(fnkwargs.get('payload', {}))
            return obj
        elif action == 'auth':
            return auth_configuration()
        else:
            raise NotImplementedError('Action {} is not supported by mock_kqueen_request'.format(action))
    monkeypatch.setattr('kqueen_ui.generic_views.KQueenView.kqueen_request', mock_kqueen_request)

    # TODO: should always use wrapper, so I don't need to patch single manager method directly on client
    def mock_policy(self, uuid):
        response = KQueenResponse()
        response.data = default_policy()
        return response
    monkeypatch.setattr('kqueen_ui.api.OrganizationManager.policy', mock_policy)

    def mock_engines(self):
        response = KQueenResponse()
        response.data = provisioner_engines()
        return response
    monkeypatch.setattr('kqueen_ui.api.ProvisionerManager.engines', mock_engines)
