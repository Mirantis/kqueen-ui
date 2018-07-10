import pytest

# load constants
from kqueen_ui.utils.filters import CLUSTER_STATE_MAP, PROVISIONER_STATE_MAP, USER_STATE_MAP
# load filters
from kqueen_ui.utils.filters import cluster_status_icon, provisioner_status_icon_class, user_status_icon_class
# load context processors
from kqueen_ui.utils.filters import base_url, policy_handler


@pytest.mark.parametrize('cluster,icon_class',
                         [({'metadata': {'status_message': 'Error creating server'}, 'state': k}, v)
                          for k, v in CLUSTER_STATE_MAP.items()])
def test_cluster_status_icon_class(cluster, icon_class):
    assert icon_class in cluster_status_icon(cluster)
    assert any(item in cluster_status_icon(cluster) for item in ['Error creating server', cluster['state']])


@pytest.mark.parametrize('state,icon_class', PROVISIONER_STATE_MAP.items())
def test_provisioner_status_icon_class(state, icon_class):
    assert icon_class == provisioner_status_icon_class(state)


@pytest.mark.parametrize('state,icon_class', USER_STATE_MAP.items())
def test_user_status_icon_class(state, icon_class):
    assert icon_class == user_status_icon_class(state)


def test_base_url(app):
    with app.test_request_context('http://localhost:8000/ui/test'):
        url = base_url()
        assert url.get('base_url') == 'http://localhost:8000'


@pytest.mark.parametrize('resource_name,action,admin_res,member_res', [
    ('cluster', 'create', True, True),
    ('cluster', 'delete', True, False),
    ('cluster', 'get', True, True),
    ('cluster', 'list', True, True),
    ('cluster', 'update', True, False),
    ('organization', 'create', False, False),
    ('organization', 'delete', False, False),
    ('organization', 'get', True, True),
    ('organization', 'list', True, True),
    ('organization', 'update', False, False),
    ('provisioner', 'create', True, True),
    ('provisioner', 'delete', True, False),
    ('provisioner', 'get', True, True),
    ('provisioner', 'list', True, True),
    ('provisioner', 'update', True, True),
    ('user', 'create', True, False),
    ('user', 'delete_member', True, False),
    ('user', 'delete_admin', True, False),
    ('user', 'delete_superadmin', False, False),
    ('user', 'get', True, True),
    ('user', 'list', True, True),
    ('user', 'update', True, False)
])
def test_policy_handler(
        cluster,
        organization,
        provisioner,
        user,
        default_policy,
        admin,
        member,
        superadmin,
        resource_name,
        action,
        admin_res,
        member_res):
    resources = {
        'cluster': cluster,
        'organization': organization,
        'provisioner': provisioner,
        'user': user
    }
    resource = resources.get(resource_name)
    policy_rule = '{}:{}'.format(resource_name, action)
    if policy_rule == 'user:delete':
        policy_rule = '{}_{}'.format(policy_rule, resource.role)
    _authorized = policy_handler()
    authorized = _authorized.get('is_authorized')

    session = {
        'policy': default_policy,
        'user': admin
    }
    assert authorized(session, policy_rule, resource) is admin_res
    session = {
        'policy': default_policy,
        'user': member
    }
    assert authorized(session, policy_rule, resource) is member_res
    session = {
        'policy': default_policy,
        'user': superadmin
    }
    assert authorized(session, policy_rule, resource) is True
