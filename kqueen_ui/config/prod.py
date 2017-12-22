from .base import BaseConfig


class Config(BaseConfig):
    DEBUG = False
    LOG_LEVEL = 'INFO'

    # KQueen UI endpoints
    HOST = '0.0.0.0'
    PORT = 8000

    # App secret
    SECRET_KEY = 'secret'
    SECURITY_PASSWORD_SALT = 'secret_salt'

    # Addons
    ENABLE_ADDONS = False

    # Registration
    ENABLE_PUBLIC_REGISTRATION = True
