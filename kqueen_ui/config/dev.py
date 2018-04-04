from .base import BaseConfig


class Config(BaseConfig):
    DEBUG = True
    LOG_CONFIG = 'kqueen_ui/utils/logger_config.yml'

    # KQueen UI endpoints
    HOST = '0.0.0.0'
    PORT = 5080

    # App secret
    SECRET_KEY = 'SecretSecretSecret123'
    SECURITY_PASSWORD_SALT = 'secret_salt'

    # Addons
    ENABLE_ADDONS = False
    ENABLE_PUBLIC_REGISTRATION = True

    # Auth configuration

    # Enable email notifications to user
    LDAP_AUTH_NOTIFY = False
    LOCAL_AUTH_NOTIFY = True
