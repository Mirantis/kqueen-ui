from .server import app

from flask_babel import Babel
from flask_cache import Cache


babel = Babel(app)
cache = Cache(app, config=app.config['CACHE'])
