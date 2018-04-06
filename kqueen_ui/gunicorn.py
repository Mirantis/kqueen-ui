from kqueen_ui.config.utils import kqueen_ui_config


import multiprocessing

app_config = kqueen_ui_config

bind = "{host}:{port}".format(
    host=app_config.get('HOST'),
    port=app_config.get('PORT'),
)
timeout = 180
workers = multiprocessing.cpu_count() * 2 + 1
worker_class = 'gthread'
