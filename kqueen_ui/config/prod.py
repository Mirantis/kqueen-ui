from .base import BaseConfig


class Config(BaseConfig):
    DEBUG = False
    LOG_CONFIG = 'kqueen_ui/utils/logger_config.yml'

    # KQueen UI endpoints
    HOST = '0.0.0.0'
    PORT = 5080

    # App secret
    SECRET_KEY = 'secret'
    SECURITY_PASSWORD_SALT = 'secret_salt'

    # Addons
    ENABLE_ADDONS = False

    # Registration
    ENABLE_PUBLIC_REGISTRATION = True
