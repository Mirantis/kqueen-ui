from flask import url_for
from kqueen_ui.api import KQueenResponse

import pytest


@pytest.mark.parametrize('view,values', [
    ('manager.overview', {}),
    ('manager.organization_create', {}),
    ('manager.organization_delete', {'organization_id': 1}),
    ('manager.organization_detail', {'organization_id': 1}),
    ('manager.member_create', {'organization_id': 1}),
    ('manager.member_change_role', {'organization_id': 1, 'user_id': 1})
])
def test_login_required(client, view, values):
    response = client.get(url_for(view, **values))
    assert response.status_code == 302


@pytest.mark.parametrize('view,values', [
    ('manager.overview', {}),
    ('manager.organization_create', {}),
    ('manager.organization_delete', {'organization_id': 1}),
    ('manager.organization_detail', {'organization_id': 1}),
    ('manager.member_create', {'organization_id': 1}),
    ('manager.member_change_role', {'organization_id': 1, 'user_id': 1})
])
def test_superadmin_required(client_login, view, values):
    response = client_login.get(url_for(view, **values))
    assert response.status_code == 302


@pytest.mark.parametrize('view,values,lookup_html', [
    ('manager.overview', {}, ['<h2>Overview</h2>']),
    ('manager.organization_create', {}, ['<h2>Create Organization</h2>']),
    ('manager.organization_detail', {'organization_id': 1}, ['<h2>Manage PytestOrg</h2>']),
    ('manager.member_create', {'organization_id': 1}, ['<h2>Add Member</h2>']),
    ('manager.member_change_role', {'organization_id': 1, 'user_id': 1}, ['<h2>Change Role</h2>'])
])
def test_render_view(client_login_superadmin, view, values, lookup_html):
    response = client_login_superadmin.get(url_for(view, **values))
    html = response.data.decode('utf-8')
    assert response.status_code == 200
    for item in lookup_html:
        assert item in html


def test_data_clusters(client_login_superadmin, cluster, monkeypatch):
    response = client_login_superadmin.get(url_for('manager.data_clusters', page=1))
    assert response.status_code == 200
    assert response.json['response'] == 200
    assert '<table' in response.json['body']


def test_data_provisioners(client_login_superadmin, provisioner, monkeypatch):
    response = client_login_superadmin.get(url_for('manager.data_provisioners', page=1))
    assert response.status_code == 200
    assert response.json['response'] == 200
    assert '<table' in response.json['body']


def test_organization_create(client_login_superadmin, organization, monkeypatch):
    # POST
    def mock_organization_list(self):
        response = KQueenResponse()
        response.data = [organization]
        return response
    monkeypatch.setattr('kqueen_ui.api.OrganizationManager.list', mock_organization_list)

    form_data = {
        'organization_name': 'New PytestOrg'
    }
    response = client_login_superadmin.post(url_for('manager.organization_create'), data=form_data)
    assert response.status_code == 302
    assert response.headers['Location'].endswith(url_for('manager.overview'))


def test_organization_delete(client_login_superadmin, organization):
    response = client_login_superadmin.get(url_for('manager.organization_delete', organization_id=organization['id']))
    assert response.status_code == 302
    assert response.headers['Location'].endswith(url_for('manager.overview'))


def test_member_create(client_login_superadmin, user, monkeypatch):
    # POST
    def mock_user_list(self):
        response = KQueenResponse()
        response.data = [user]
        return response
    monkeypatch.setattr('kqueen_ui.api.UserManager.list', mock_user_list)

    form_data = {'role': 'member',
                 'username__local': 'test@test.ru',
                 'auth_method': 'local',
                 'username__ldap': ''}
    organization_id = user['organization']['id']
    response = client_login_superadmin.post(url_for('manager.member_create', organization_id=organization_id), data=form_data)
    assert response.status_code == 302
    assert response.headers['Location'].endswith(url_for('manager.organization_detail', organization_id=organization_id))


def test_member_change_role(client_login_superadmin, user):
    # POST
    form_data = {
        'role': 'member'
    }
    organization_id = user['organization']['id']
    response = client_login_superadmin.post(url_for('manager.member_change_role', organization_id=organization_id, user_id=user['id']), data=form_data)
    assert response.status_code == 302
    assert response.headers['Location'].endswith(url_for('manager.organization_detail', organization_id=organization_id))
