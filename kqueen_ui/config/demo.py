from .base import BaseConfig


class Config(BaseConfig):
    DEBUG = False
    LOG_LEVEL = 'INFO'

    # KQueen UI endpoints
    HOST = '0.0.0.0'
    PORT = 5080

    # App secret
    SECRET_KEY = 'SecretSecretSecret123'
    SECURITY_PASSWORD_SALT = 'secret_salt'

    # Addons
    ENABLE_ADDONS = False
