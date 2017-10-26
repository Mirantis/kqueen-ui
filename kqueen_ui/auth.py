from kqueen_ui.api import KQueenAPIClient

import logging

logger = logging.getLogger(__name__)


def authenticate(username, password):
    client = KQueenAPIClient(username=username, password=password)
    token = client.token
    if token:
        _users = client.user.list()
        users = _users.data
        if not _users.error:
            return ([u for u in users if u['username'] == username][0], token)
        logger.error(_users.error)
    return ({}, '')
