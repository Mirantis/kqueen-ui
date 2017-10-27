from kqueen_ui.blueprints.ui.utils import get_kqueen_client

import logging

logger = logging.getLogger(__name__)


def authenticate(username, password):
    user = {}
    client = get_kqueen_client(username=username, password=password)
    token, error = client.base.login()
    if token:
        _users = client.user.list()
        users = _users.data
        user = [u for u in users if u['username'] == username][0]
        user['token'] = token
    return user, error
