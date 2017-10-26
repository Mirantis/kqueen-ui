from kqueen_ui.api import KQueenAPIClient

import logging

logger = logging.getLogger(__name__)


def authenticate(username, password):
    user = {}
    client = KQueenAPIClient(username=username, password=password)
    token, error = client.base.login()
    if token:
        _users = client.user.list()
        users = _users.data
        user = [u for u in users if u['username'] == username][0]
        user['token'] = token
    return user, error
