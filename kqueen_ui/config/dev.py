from .base import BaseConfig


class Config(BaseConfig):
    DEBUG = True
    LOG_LEVEL = 'DEBUG'

    # App secret
    SECRET_KEY = 'secret'
    SECURITY_PASSWORD_SALT = 'secret_salt'

    ENABLE_PUBLIC_REGISTRATION = True
