from .base import BaseConfig


class Config(BaseConfig):
    DEBUG = True
    LOG_LEVEL = 'DEBUG'
    LOG_CONFIG = 'kqueen_ui/utils/logger_config.yml'

    # App secret
    SECRET_KEY = 'secret'
    SECURITY_PASSWORD_SALT = 'secret_salt'

    ENABLE_PUBLIC_REGISTRATION = True
