from flask import url_for
from kqueen_ui.server import create_app
from unittest.mock import Mock, patch

import pytest
import uuid

config_file = 'config/test.py'


@pytest.fixture
def app():
    app = create_app(config_file=config_file)
    return app


@pytest.fixture
def organization():
    organization = {
        'id': uuid.uuid4(),
        'name': 'PytestOrg',
        'namespace': 'pytestorg'
    }
    return organization


@pytest.fixture
def user():
    user = {
        'id': uuid.uuid4(),
        'username': 'pytest',
        'password': 'pytest',
        'email': 'pytest@python.org',
        'organization': organization()['id']
    }
    return user


@pytest.fixture
def token():
    return 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE1MDg4NTkwNzksIm5iZiI6MTUwODg1NTQ3OSwiaWRlbnRpdHkiOiIzNmIzMDBmMS0yZDNmLTQ2NzAtOTI4NS0wNTEyOGYzYjM5NmIiLCJpYXQiOjE1MDg4NTU0Nzl9.wGx5bXq5Xmf3lZSXt38BGf4wTg115qxM5Blze4ZYAj0'


@patch('kqueen_ui.blueprints.ui.views.authenticate')
def _login(client, mock_get):
    _user = user()
    _token = token()
    mock_get.return_value = (_user, _token)
    client.post(url_for('ui.login'), data={
        'username': _user['username'],
        'password': _user['password']
    })
    return client


@pytest.fixture
def client_login(client):
    return _login(client)
