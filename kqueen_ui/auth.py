from itsdangerous import URLSafeTimedSerializer
from flask import current_app as app
from kqueen_ui.api import get_kqueen_client
from kqueen_ui.config import current_config

import logging

logger = logging.getLogger('kqueen_ui')
config = current_config()


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


def is_authorized(session, policy_value, resource=None):
    """
    Evaluate if given user fulfills requirements of the given
    policy_value.

    Example:
        >>> user.get_dict()
        >>> {'username': 'jsmith', ..., 'role': 'member'}
        >>> is_authorized(user, "ALL")
        True
        >>> is_authorized(user, "IS_ADMIN")
        False

    Args:
        session (dict): session data
        policy_value (string or list): Condition written using shorthands

    Returns:
        bool: authorized or not
    """
    if 'user' not in session or 'policy' not in session:
        logger.error('Cannot evaluate policy without "user" and "policy" keys in session')
        return False

    # magic keywords
    USER = session['user']['id']                                          # noqa: F841
    ORGANIZATION = session['user']['organization']['id']                  # noqa: F841
    ROLE = session['user']['role']
    if resource:
        if 'owner' in resource:
            OWNER = resource['owner']['id']                               # noqa: F841
            OWNER_ORGANIZATION = resource['owner']['organization']['id']  # noqa: F841
        elif 'role' in resource:
            # awkward way to detect user
            OWNER = resource['id']                                        # noqa: F841
            OWNER_ORGANIZATION = resource['organization']['id']           # noqa: F841
        elif 'namespace' in resource:
            # awkward way to detect organization
            OWNER_ORGANIZATION = resource['id']                           # noqa: F841

    # predefined conditions for evaluation
    conditions = {
        'IS_ADMIN': 'ROLE == "admin"',
        'IS_SUPERADMIN': 'ROLE == "superadmin"',
        'IS_OWNER': 'USER == OWNER',
        'ADMIN_OR_OWNER': 'ROLE == "admin" or USER == OWNER',
        'ALL': 'True'
    }

    try:
        condition = conditions[policy_value]
    except KeyError:
        logger.error('Policy evaluation failed. Invalid rule: {}'.format(str(policy_value)))
        return False

    if ROLE == 'superadmin':
        # no point in checking anything here
        return True

    try:
        authorized = eval(condition)
        if not isinstance(authorized, bool):
            logger.error('Policy evaluation did not return boolean: {}'.format(str(authorized)))
            authorized = False
    except Exception as e:
        logger.error('Policy evaluation failed: {}'.format(repr(e)))
        authorized = False
    return authorized
