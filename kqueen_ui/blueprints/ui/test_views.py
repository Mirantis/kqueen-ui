from flask import url_for
from kqueen_ui.api import KQueenResponse

import pytest


@pytest.mark.parametrize('view,values', [
    ('ui.index', {}),
    ('ui.logout', {}),
    ('ui.organization_manage', {}),
    ('ui.user_invite', {}),
    ('ui.user_delete', {'user_id': 1}),
    ('ui.user_change_password', {}),
    ('ui.user_profile', {}),
    ('ui.provisioner_create', {}),
    ('ui.provisioner_delete', {'provisioner_id': 1}),
    ('ui.cluster_create', {}),
    ('ui.cluster_delete', {'cluster_id': 1}),
    ('ui.cluster_deployment_status', {'cluster_id': 1}),
    ('ui.cluster_detail', {'cluster_id': 1}),
    ('ui.cluster_kubeconfig', {'cluster_id': 1}),
    ('ui.cluster_topology_data', {'cluster_id': 1})
])
def test_login_required(client, view, values):
    response = client.get(url_for(view, **values))
    assert response.status_code == 302


@pytest.mark.parametrize('view,values,lookup_html', [
    ('ui.index', {}, ['<h2>Overview</h2>', 'pytest-provisioner', 'pytest-cluster']),
    ('ui.organization_manage', {}, ['<h2>Manage PytestOrg</h2>']),
    ('ui.user_invite', {}, ['h2>Invite Member</h2>']),
    ('ui.user_change_password', {}, ['<h2>Change Password</h2>']),
    ('ui.user_profile', {}, ['<h2>User Profile</h2>']),
    ('ui.provisioner_create', {}, ['<h2>Create Provisioner</h2>']),
    ('ui.cluster_create', {}, ['<h2>Deploy Kubernetes Cluster</h2>']),
    ('ui.cluster_detail', {'cluster_id': '1868f6f4-1dbb-4555-ba46-1d2924e81f5e'}, ['<h2>Cluster pytest-cluster detail</h2>', '<td class="col-md-3">ip-10-0-10-95.us-west-2.compute.internal</td>']),
])
def test_render_view(client_login, view, values, lookup_html):
    response = client_login.get(url_for(view, **values))
    html = response.data.decode('utf-8')
    assert response.status_code == 200
    for item in lookup_html:
        assert item in html


def test_logout(client_login, app):
    response = client_login.get(url_for('ui.logout'))
    assert response.status_code == 302
    assert response.headers['Location'].endswith(url_for('ui.index'))


def test_user_invite(client_login):
    form_data = {
        'email': 'test@test.org',
        'auth_method': 'local'
    }
    response = client_login.post(url_for('ui.user_invite'), data=form_data)
    assert response.status_code == 302
    assert response.headers['Location'].endswith(url_for('ui.organization_manage'))


def test_user_reinvite(client_login, user):
    response = client_login.get(url_for('ui.user_reinvite', user_id=user['id']))
    assert response.status_code == 302
    assert response.headers['Location'].endswith(url_for('ui.organization_manage'))


def test_user_delete(client_login, user):
    response = client_login.get(url_for('ui.user_delete', user_id=user['id']))
    assert response.status_code == 302
    assert response.headers['Location'].endswith(url_for('ui.index'))


def test_user_reset_password(client, email_token):
    response = client.get(url_for('ui.user_reset_password', token=email_token))
    html = response.data.decode('utf-8')
    assert response.status_code == 200
    assert '<h2>Set New Password</h2>' in html


def test_user_set_password(client, email_token):
    response = client.get(url_for('ui.user_set_password', token=email_token))
    html = response.data.decode('utf-8')
    assert response.status_code == 200
    assert '<h2>Set New Password</h2>' in html


def test_user_request_reset_password(client, user, monkeypatch):
    # GET
    response = client.get(url_for('ui.user_request_reset_password'))
    html = response.data.decode('utf-8')
    assert response.status_code == 200
    assert '<h2>Request Password Reset</h2>' in html

    # POST
    def mock_user_list(self):
        response = KQueenResponse()
        response.data = [user]
        return response
    monkeypatch.setattr('kqueen_ui.api.UserManager.list', mock_user_list)

    form_data = {
        'email': user['email']
    }
    response = client.post(url_for('ui.user_request_reset_password'), data=form_data)
    assert response.status_code == 302
    assert response.headers['Location'].endswith(url_for('ui.index'))


def test_provisioner_create(client_login):
    # POST
    form_data = {
        'name': 'Pytest Jenkins',
        'engine': 'kqueen.engines.JenkinsEngine',
        'password__Jenkins': 'pytest',
        'username__Jenkins': 'pytest'
    }
    response = client_login.post(url_for('ui.provisioner_create'), data=form_data)
    assert response.status_code == 302
    assert response.headers['Location'].endswith(url_for('ui.index', _anchor='provisionersTab'))


def test_provisioner_delete(client_login, provisioner):
    response = client_login.get(url_for('ui.provisioner_delete', provisioner_id=provisioner['id']))
    assert response.status_code == 302
    assert response.headers['Location'].endswith(url_for('ui.index', _anchor='provisionersTab'))


def test_cluster_create(client_login, provisioner):
    # POST
    form_data = {
        'name': 'pytest_cluster',
        'provisioner': provisioner['id']
    }
    response = client_login.post(url_for('ui.cluster_create'), data=form_data)
    assert response.status_code == 302
    assert response.headers['Location'].endswith(url_for('ui.index'))


def test_cluster_delete(client_login, cluster):
    response = client_login.get(url_for('ui.cluster_delete', cluster_id=cluster['id']))
    assert response.status_code == 302
    assert response.headers['Location'].endswith(url_for('ui.index'))


def test_cluster_resize(client_login, cluster):
    form_data = {
        'node_count': '3'
    }
    response = client_login.post(url_for('ui.cluster_resize', cluster_id=cluster['id']), data=form_data)
    assert response.status_code == 302
    assert response.headers['Location'].endswith(url_for('ui.index'))


def test_cluster_deployment_status(client_login, cluster):
    response = client_login.get(url_for('ui.cluster_deployment_status', cluster_id=cluster['id']))
    expected_keys = ['progress', 'response', 'result']
    assert response.status_code == 200
    assert set(expected_keys) == set(response.json.keys())


def test_cluster_kubeconfig(client_login, cluster):
    response = client_login.get(url_for('ui.cluster_kubeconfig', cluster_id=cluster['id']))
    assert response.status_code == 200
    assert response.json == cluster['kubeconfig']


def test_cluster_topology_data(client_login, cluster):
    response = client_login.get(url_for('ui.cluster_topology_data', cluster_id=cluster['id']))
    assert response.status_code == 200
    assert response.json == {}
