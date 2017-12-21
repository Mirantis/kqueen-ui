from flask import url_for

import pytest


@pytest.mark.parametrize('view,values', [
    ('ui.index', {}),
    ('ui.logout', {}),
    ('ui.organization_manage', {}),
    ('ui.user_invite', {}),
    ('ui.user_delete', {'user_id': 1}),
    ('ui.user_change_password', {}),
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
    ('ui.provisioner_create', {}, ['<h2>Create Provisioner</h2>']),
    ('ui.cluster_create', {}, ['<h2>Deploy Kubernetes Cluster</h2>']),
    ('ui.cluster_detail', {'cluster_id': '1868f6f4-1dbb-4555-ba46-1d2924e81f5e'}, ['<h2>Cluster pytest-cluster detail</h2>', '<td>ip-10-0-10-95.us-west-2.compute.internal</td>']),
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


def test_user_request_reset_password(client):
    response = client.get(url_for('ui.user_request_reset_password'))
    html = response.data.decode('utf-8')
    assert response.status_code == 200
    assert '<h2>Request Password Reset</h2>' in html


def test_provisioner_delete(client_login, provisioner):
    response = client_login.get(url_for('ui.provisioner_delete', provisioner_id=provisioner['id']))
    assert response.status_code == 302
    assert response.headers['Location'].endswith(url_for('ui.index'))


def test_cluster_delete(client_login, cluster):
    response = client_login.get(url_for('ui.cluster_delete', cluster_id=cluster['id']))
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
