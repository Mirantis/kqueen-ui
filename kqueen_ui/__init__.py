from .server import app

from flask import session
from flask_babel import Babel
from flask_cache import Cache

babel = Babel(app)
cache = Cache(app, config=app.config['CACHE'])


@babel.timezoneselector
def get_timezone():
    user_metadata = session.get('user', {}).get('metadata', {})
    return user_metadata.get('timezone')
