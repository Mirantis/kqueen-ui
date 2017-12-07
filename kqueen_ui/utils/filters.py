from kqueen_ui.config import current_config

config = current_config().to_dict()

CLUSTER_STATE_MAP = {
    config['CLUSTER_OK_STATE']: 'mdi-cloud-check',
    config['CLUSTER_ERROR_STATE']: 'mdi-cloud-off-outline',
    config['CLUSTER_PROVISIONING_STATE']: 'mdi-cloud-sync',
    config['CLUSTER_DEPROVISIONING_STATE']: 'mdi-cloud-sync',
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


def cluster_status_icon_class(status):
    return CLUSTER_STATE_MAP.get(status, 'mdi-alert-circle-outline')


def provisioner_status_icon_class(status):
    return PROVISIONER_STATE_MAP.get(status, 'mdi-alert-outline')


def user_status_icon_class(status):
    return USER_STATE_MAP.get(status, 'mdi-alert-outline')


filters = {
    'cluster_status_icon_class': cluster_status_icon_class,
    'provisioner_status_icon_class': provisioner_status_icon_class,
    'user_status_icon_class': user_status_icon_class
}
