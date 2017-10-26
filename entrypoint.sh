#!/bin/bash

exec gunicorn --bind 0.0.0.0:5080 --workers 4 kqueen_ui.wsgi
