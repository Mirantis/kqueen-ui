from kqueen_ui.blueprints.ui.utils import get_kqueen_client

import logging

logger = logging.getLogger(__name__)


def authenticate(username, password):
    user = {}
    client = get_kqueen_client(username=username, password=password)
    token, error = client.base.login()
    if token:
        _user = client.user.whoami()
        user = _user.data
        user['token'] = token
    return user, error
