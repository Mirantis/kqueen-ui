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


def test_index(client_login, app, monkeypatch):
    def kqueen_request(*args, **kwargs):
        return []
    monkeypatch.setattr(KQueenView, 'kqueen_request', kqueen_request)
    response = client_login.get(url_for('ui.index'))
    assert response.status_code == 200


def test_logout(client_login, app):
    response = client_login.get(url_for('ui.logout'))
    assert response.status_code == 302
    assert response.headers['Location'].endswith(url_for('ui.index'))
