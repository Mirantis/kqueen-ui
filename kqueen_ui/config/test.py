from .base import BaseConfig


class Config(BaseConfig):
    DEBUG = True
    LOG_CONFIG = 'kqueen_ui/utils/logger_config.yml'

    # CSRF settings
    CSRF_ENABLED = False
    WTF_CSRF_ENABLED = False

    # App secret
    SECRET_KEY = 'secret'
    SECURITY_PASSWORD_SALT = 'secret_salt'

    # Addons
    ENABLE_ADDONS = False
    ENABLE_PUBLIC_REGISTRATION = True

    # Auth configuration

    # Enable email notifications to user
    LDAP_AUTH_NOTIFY = False
    LOCAL_AUTH_NOTIFY = True
