from .config import current_config

from flask import Flask, redirect, request, url_for
from kqueen_ui.blueprints.manager.views import manager
from kqueen_ui.blueprints.registration.views import registration
from kqueen_ui.blueprints.ui.views import ui
from kqueen_ui.exceptions import KQueenAPIException
from kqueen_ui.utils.filters import filters, context_processors
from kqueen_ui.utils.loggers import setup_logging

import logging

# Logging configuration
config = current_config(config_file=None)

setup_logging(config.get('LOG_CONFIG'), config.get('DEBUG'))
logger = logging.getLogger('kqueen_ui')


def create_app(config_file=None):
    app = Flask(__name__, static_folder='./asset/static')

    from .converters import ListConverter  # it's here to avoid circular imports
    app.url_map.converters['list'] = ListConverter

    app.register_blueprint(manager, url_prefix='/manager')
    app.register_blueprint(registration, url_prefix='/registration')
    app.register_blueprint(ui, url_prefix='/ui')

    # load configuration
    config = current_config(config_file)
    app.config.from_mapping(config.to_dict())

    app.jinja_env.filters.update(filters)
    for cp in context_processors:
        app.template_context_processors[None].append(cp)

    return app


app = create_app()


@app.route('/')
def root():
    return redirect(url_for('ui.index'), code=302)


@app.errorhandler(KQueenAPIException)
def handle_kqueen_api_exception(e):
    redirect_to = url_for('ui.index')
    if request.url.endswith(redirect_to):
        redirect_to = url_for('ui.logout')
    return redirect(redirect_to)


def run():
    logger.debug('kqueen_ui starting')
    app.run(
        host=app.config.get('HOST'),
        port=int(app.config.get('PORT'))
    )
