from flask import request
from kqueen_ui.auth import is_authorized
from kqueen_ui.config import current_config
from urllib.parse import urlsplit

import yaml as pyaml

config = current_config().to_dict()

CLUSTER_STATE_MAP = {
    config['CLUSTER_OK_STATE']: 'mdi-cloud-check',
    config['CLUSTER_ERROR_STATE']: 'mdi-cloud-off-outline',
    config['CLUSTER_PROVISIONING_STATE']: 'loading-icon',
    config['CLUSTER_DEPROVISIONING_STATE']: 'mdi-cloud-sync',
    config['CLUSTER_RESIZING_STATE']: 'loading-icon',
    config['CLUSTER_UNKNOWN_STATE']: 'mdi-alert-outline'
}

PROVISIONER_STATE_MAP = {
    config['PROVISIONER_OK_STATE']: 'mdi-checkbox-marked-circle-outline',
    config['PROVISIONER_ERROR_STATE']: 'mdi-close-circle-outline',
    config['PROVISIONER_UNKNOWN_STATE']: 'mdi-alert-circle-outline'
}

USER_STATE_MAP = {
    'Active': 'mdi-checkbox-marked-circle-outline',
    'Disabled': 'mdi-close-circle-outline'
}


def cluster_status_icon(status):
    icon = '<i class="mdi {}" title="{}"></i>'.format(
        CLUSTER_STATE_MAP.get(status, 'mdi-alert-circle-outline'),
        status
    )
    if status in [config['CLUSTER_PROVISIONING_STATE'], config['CLUSTER_RESIZING_STATE']]:
        icon = '<div class="icon-container"><div class="{}" title="{}"></div></div>'.format(
            CLUSTER_STATE_MAP.get(status, 'mdi-alert-circle-outline'),
            status
        )
    return icon


def provisioner_status_icon_class(status):
    return PROVISIONER_STATE_MAP.get(status, 'mdi-alert-outline')


def user_status_icon_class(status):
    return USER_STATE_MAP.get(status, 'mdi-alert-outline')


def yaml(string):
    return pyaml.safe_dump(string, indent=2, default_flow_style=False)


filters = {
    'cluster_status_icon': cluster_status_icon,
    'provisioner_status_icon_class': provisioner_status_icon_class,
    'user_status_icon_class': user_status_icon_class,
    'yaml': yaml
}


def base_url():
    base_url = urlsplit(request.url).scheme + '://' + urlsplit(request.url).netloc
    return dict(base_url=base_url)


def policy_handler():
    def authorized(session, action, resource=None):
        policy_value = session['policy'].get(action, '-')
        return is_authorized(session, policy_value, resource)
    return dict(is_authorized=authorized)


context_processors = [
    base_url,
    policy_handler
]
