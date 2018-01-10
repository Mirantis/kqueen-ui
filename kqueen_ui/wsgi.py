"""WGSI module to run application using Gunicorn server."""

from kqueen_ui import app as application
from werkzeug.contrib.fixers import ProxyFix

if __name__ == '__main__':
    application.wsgi_application = ProxyFix(application.wsgi_application)
    application.run()
