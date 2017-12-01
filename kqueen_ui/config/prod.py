from .base import BaseConfig


class Config(BaseConfig):
    DEBUG = False
    LOG_LEVEL = 'INFO'

    # KQueen UI endpoints
    KQUEEN_UI_HOST = '0.0.0.0'
    KQUEEN_UI_PORT = 8000

    # App secret
    SECRET_KEY = 'secret'
    SECURITY_PASSWORD_SALT = 'secret_salt'
