from kqueen_ui.api import KQueenAPIClient


def authenticate(username, password):
    client = KQueenAPIClient(username=username, password=password)
    token = client.token
    if token:
        users = client.user.list()
        return ([u for u in users if u['username'] == username][0], token)
    return ({}, '')
