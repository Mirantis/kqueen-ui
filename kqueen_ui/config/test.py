from .base import BaseConfig


class Config(BaseConfig):
    DEBUG = True
    LOG_CONFIG = 'kqueen_ui/utils/logger_config.yml'

    # App secret
    SECRET_KEY = 'secret'
    SECURITY_PASSWORD_SALT = 'secret_salt'

    # CSRF settings
    CSRF_ENABLED = False
    WTF_CSRF_ENABLED = False

    ENABLE_PUBLIC_REGISTRATION = True

    # Authentication choices
    AUTH_OPTIONS = {
        'local': {
            'label': 'Local',
            'notify': True
        },
        'ldap': {
            'label': 'LDAP',
            'notify': False
        }
    }
