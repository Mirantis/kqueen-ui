#!/bin/bash

# STATIC_DIR - set this to copy static files before start

if [ ! -z "${STATIC_DIR}" ]; then
	echo "Running in Docker compose mode"
	mkdir -p "${STATIC_DIR}"
	cp -vr /code/kqueen_ui/asset/static/* "${STATIC_DIR}"
fi

exec gunicorn --bind 0.0.0.0:5080 --workers 4 kqueen_ui.wsgi
