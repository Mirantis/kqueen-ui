from flask import url_for
from kqueen_ui.generic_views import KQueenView
from unittest.mock import patch

import pytest


@pytest.mark.parametrize('view,values', [
    ('ui.index', {}),
    ('ui.logout', {}),
    ('ui.organization_manage', {}),
    ('ui.user_invite', {}),
    ('ui.user_delete', {'user_id': 1}),
    ('ui.user_change_password', {}),
    ('ui.provisioner_create', {'provisioner_id': 1}),
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


def test_index(client_login, app, mock_kqueen_request, monkeypatch):
    monkeypatch.setattr(KQueenView, 'kqueen_request', mock_kqueen_request)
    response = client_login.get(url_for('ui.index'))
    html = response.data.decode('utf-8')
    assert response.status_code == 200
    assert '<h2>Overview</h2>' in html
    assert 'pytest-provisioner' in html
    assert 'pytest-cluster' in html


def test_logout(client_login, app):
    response = client_login.get(url_for('ui.logout'))
    assert response.status_code == 302
    assert response.headers['Location'].endswith(url_for('ui.index'))


def test_organization_manage(client_login, mock_kqueen_request, monkeypatch):
    monkeypatch.setattr(KQueenView, 'kqueen_request', mock_kqueen_request)
    response = client_login.get(url_for('ui.organization_manage'))
    html = response.data.decode('utf-8')
    assert response.status_code == 200
    assert '<h2>Manage PytestOrg</h2>' in html


def test_user_invite(client_login):
    response = client_login.get(url_for('ui.user_invite'))
    html = response.data.decode('utf-8')
    assert response.status_code == 200
    assert '<h2>Invite Member</h2>' in html


def test_user_delete(client_login, user, mock_kqueen_request, monkeypatch):
    monkeypatch.setattr(KQueenView, 'kqueen_request', mock_kqueen_request)
    response = client_login.get(url_for('ui.user_delete', user_id=user['id']))
    assert response.status_code == 302
    assert response.headers['Location'].endswith(url_for('ui.index'))


def test_user_change_password(client_login):
    response = client_login.get(url_for('ui.user_change_password'))
    html = response.data.decode('utf-8')
    assert response.status_code == 200
    assert '<h2>Change Password</h2>' in html


def test_user_reset_password(client, email_token, mock_kqueen_request, monkeypatch):
    monkeypatch.setattr(KQueenView, 'kqueen_request', mock_kqueen_request)
    response = client.get(url_for('ui.user_reset_password', token=email_token))
    html = response.data.decode('utf-8')
    assert response.status_code == 200
    assert '<h2>Set New Password</h2>' in html


def test_user_request_reset_password(client):
    response = client.get(url_for('ui.user_request_reset_password'))
    html = response.data.decode('utf-8')
    assert response.status_code == 200
    assert '<h2>Request Password Reset</h2>' in html


def test_provisioner_create(client_login, mock_kqueen_request, monkeypatch):
    monkeypatch.setattr(KQueenView, 'kqueen_request', mock_kqueen_request)
    response = client_login.get(url_for('ui.provisioner_create'))
    html = response.data.decode('utf-8')
    assert response.status_code == 200
    assert '<h2>Create Provisioner</h2>' in html


def test_provisioner_delete(client_login, provisioner, mock_kqueen_request, monkeypatch):
    monkeypatch.setattr(KQueenView, 'kqueen_request', mock_kqueen_request)
    response = client_login.get(url_for('ui.provisioner_delete', provisioner_id=provisioner['id']))
    assert response.status_code == 302
    assert response.headers['Location'].endswith(url_for('ui.index'))


def test_cluster_create(client_login, mock_kqueen_request, monkeypatch):
    monkeypatch.setattr(KQueenView, 'kqueen_request', mock_kqueen_request)
    response = client_login.get(url_for('ui.cluster_create'))
    html = response.data.decode('utf-8')
    assert response.status_code == 200
    assert '<h2>Deploy Kubernetes Cluster</h2>' in html


def test_cluster_delete(client_login, cluster, mock_kqueen_request, monkeypatch):
    monkeypatch.setattr(KQueenView, 'kqueen_request', mock_kqueen_request)
    response = client_login.get(url_for('ui.cluster_delete', cluster_id=cluster['id']))
    assert response.status_code == 302
    assert response.headers['Location'].endswith(url_for('ui.index'))


def test_cluster_deployment_status(client_login, cluster):
    response = client_login.get(url_for('ui.cluster_deployment_status', cluster_id=cluster['id']))
    expected_keys = ['progress', 'response', 'result']
    assert response.status_code == 200
    assert set(expected_keys) == set(response.json.keys())


def test_cluster_detail(client_login, cluster, mock_kqueen_request, monkeypatch):
    monkeypatch.setattr(KQueenView, 'kqueen_request', mock_kqueen_request)
    response = client_login.get(url_for('ui.cluster_detail', cluster_id=cluster['id']))
    html = response.data.decode('utf-8')
    assert response.status_code == 200
    assert '<h2>Cluster pytest-cluster detail</h2>'
    assert '<td>ip-10-0-10-95.us-west-2.compute.internal</td>' in html


def test_cluster_kubeconfig(client_login, cluster, mock_kqueen_request, monkeypatch):
    monkeypatch.setattr(KQueenView, 'kqueen_request', mock_kqueen_request)
    response = client_login.get(url_for('ui.cluster_kubeconfig', cluster_id=cluster['id']))
    assert response.status_code == 200
    assert response.json == cluster['kubeconfig']


def test_cluster_kubeconfig(client_login, cluster, mock_kqueen_request, monkeypatch):
    monkeypatch.setattr(KQueenView, 'kqueen_request', mock_kqueen_request)
    response = client_login.get(url_for('ui.cluster_kubeconfig', cluster_id=cluster['id']))
    assert response.status_code == 200
    assert response.json == cluster['kubeconfig']


def test_cluster_topology_data(client_login, cluster, mock_kqueen_request, monkeypatch):
    monkeypatch.setattr(KQueenView, 'kqueen_request', mock_kqueen_request)
    response = client_login.get(url_for('ui.cluster_topology_data', cluster_id=cluster['id']))
    assert response.status_code == 200
    assert response.json == {}
