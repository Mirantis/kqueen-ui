from collections import OrderedDict
from flask import request
from kqueen_ui.api import get_kqueen_client
from kqueen_ui.auth import is_authorized
from kqueen_ui.config import current_config
from urllib.parse import urlsplit

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


def base_url():
    base_url = urlsplit(request.url).scheme + '://' + urlsplit(request.url).netloc
    return dict(base_url=base_url)


def policy_handler():
    def authorized(session, action, resource=None):
        policy_value = session['policy'].get(action, '-')
        return is_authorized(session, policy_value, resource)
    return dict(is_authorized=authorized)


def sanitize_resource_metadata():
    from kqueen_ui import cache

    def metaparser(session, clusters=[], provisioners=[]):
        token = session.get('user', {}).get('token', None)
        client = None
        engines = cache.get('provisioner-engines')
        if not engines:
            abort = False
            if token:
                client = get_kqueen_client(token=token)
            else:
                abort = True
            if client:
                engines_res = client.provisioner.engines()
                if engines_res.status > 200:
                    abort = True
                else:
                    engines = engines_res.data
                    cache.set('provisioner-engines', engines, timeout=5 * 60)
            if abort:
                for cluster in clusters:
                    cluster['metadata'] = {}
                for provisioner in provisioners:
                    provisioner['parameters'] = {}
                return clusters, provisioners

        for cluster in clusters:
            cluster_engine = cluster.get('provisioner', {}).get('engine')
            _engine_params = [e['parameters'] for e in engines if e['name'] == cluster_engine]
            if not len(_engine_params) == 1:
                del cluster['metadata']
                continue
            engine_params = _engine_params[0].get('cluster')
            for param_name, param in engine_params.items():
                if param['type'] not in ['text', 'integer', 'select']:
                    try:
                        cluster['metadata'][param_name] = '*****************'
                    except KeyError:
                        pass
            cluster['metadata'] = OrderedDict(sorted(cluster['metadata'].items(), key=lambda t: t[0]))

        for provisioner in provisioners:
            provisioner_engine = provisioner.get('engine')
            _engine_params = [e['parameters'] for e in engines if e['name'] == provisioner_engine]
            if not len(_engine_params) == 1:
                del provisioner['parameters']
                continue
            engine_params = _engine_params[0].get('provisioner')
            for param_name, param in engine_params.items():
                if param['type'] not in ['text', 'integer', 'select']:
                    try:
                        provisioner['parameters'][param_name] = '*****************'
                    except KeyError:
                        pass
            provisioner['parameters'] = OrderedDict(sorted(provisioner['parameters'].items(), key=lambda t: t[0]))

        return clusters, provisioners
    return dict(sanitize_resource_metadata=metaparser)


context_processors = [
    base_url,
    policy_handler,
    sanitize_resource_metadata
]
