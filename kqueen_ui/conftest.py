from datetime import datetime
from flask import url_for
from kqueen_ui.auth import generate_confirmation_token
from kqueen_ui.server import create_app
from unittest.mock import patch

import json
import pytest
import uuid

config_file = 'config/test.py'
cluster_uuid = uuid.uuid4()
organization_uuid = uuid.uuid4()
provisioner_uuid = uuid.uuid4()
user_uuid = uuid.uuid4()


@pytest.fixture
def app():
    app = create_app(config_file=config_file)
    app.testing = True
    return app


@pytest.fixture
def organization():
    organization = {
        'id': organization_uuid,
        'name': 'PytestOrg',
        'namespace': 'pytestorg'
    }
    return organization


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
        'token': token()
    }
    return user


@pytest.fixture
def provisioner():
    provisioner = {
        'id': provisioner_uuid,
        'name': 'pytest-provisioner',
        'engine': 'kqueen.engines.JenkinsEngine',
        'state': 'OK',
        'parmeters': {
            'username': 'pytest',
            'password': 'pytest'
        },
        'created_at': datetime.utcnow()
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
def cluster():
    cluster = {
        'id': cluster_uuid,
        'name': 'pytest-cluster',
        'provisioner': provisioner(),
        'state': 'OK',
        'kubeconfig': kubeconfig(),
        'metadata': {},
        'created_at': datetime.utcnow()
    }
    return cluster


@pytest.fixture
def cluster_status():
    with open('kqueen_ui/fixtures/test_cluster_status.json', 'r') as stream:
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
    return generate_confirmation_token(_user['email'])


@patch('kqueen_ui.blueprints.ui.views.authenticate')
def _login(client, mock_get):
    _user = user()
    mock_get.return_value = (_user, None)
    client.post(url_for('ui.login'), data={
        'username': _user['username'],
        'password': _user['password']
    })
    return client


@pytest.fixture
def client_login(client):
    return _login(client)


@pytest.fixture
def mock_kqueen_request():
    def mock(self, resource, action, fnargs=(), fnkwargs={}, service=False):
        if resource == 'cluster':
            obj = cluster()
        elif resource == 'provisioner':
            obj = provisioner()
        elif resource == 'organization':
            obj = organization()
        elif resource == 'user':
            obj = user()
        else:
            raise NotImplementedError('Resource {} is not supported by mock_kqueen_request'.format(resource))
        if action == 'get':
            return obj
        elif action == 'list':
            return [obj]
        elif action == 'delete':
            return {'id': obj['id'], 'state': 'deleted'}
        elif action == 'engines':
            return provisioner_engines()
        elif action == 'status':
            return cluster_status()
        elif action == 'topology_data':
            return {}
        else:
            raise NotImplementedError('Action {} is not supported by mock_kqueen_request'.format(action))
    return mock
