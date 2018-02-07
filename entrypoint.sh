#!/bin/bash

# STATIC_DIR - set this to copy static files before start

if [ ! -z "${STATIC_DIR}" ]; then
	echo "Running in Docker compose mode"
	mkdir -p "${STATIC_DIR}"
	cp -vr /code/kqueen_ui/asset/static/* "${STATIC_DIR}"
fi

exec gunicorn --config kqueen_ui/gunicorn.py kqueen_ui.wsgi
