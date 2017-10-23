"""WGSI module to run application using Gunicorn server."""

from kqueen_ui.server import app as application

if __name__ == '__main__':
    application.run()
