from itsdangerous import URLSafeTimedSerializer
from flask import current_app as app
from kqueen_ui.api import get_kqueen_client

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


def generate_confirmation_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])


def confirm_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(
            token,
            salt=app.config['SECURITY_PASSWORD_SALT'],
            max_age=expiration
        )
    except Exception:
        return False
    return email
