from kqueen_ui.config import current_config

import multiprocessing
import os

app_config = current_config()

bind = "{host}:{port}".format(
    host=app_config.get('HOST'),
    port=app_config.get('PORT'),
)
timeout = 180
workers = multiprocessing.cpu_count() * 2 + 1
worker_class = 'gthread'
