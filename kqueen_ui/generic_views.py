from flask import flash, session
from flask.views import View
from kqueen_ui.api import get_kqueen_client, get_service_client

import logging

logger = logging.getLogger(__name__)


class KQueenView(View):
    """
    KQueen UI base view with methods to handle backend API calls.
    """
    def _get_kqueen_client(self):
        token = session.get('user', {}).get('token', None)
        if token:
            return get_kqueen_client(token=token)
        return None

    def _get_kqueen_service_client(self):
        return get_service_client()

    def _handle_response(self, response):
        if response:
            if response.status == -1:
                user_msg = 'Backend is unavailable at this time, please try again later.'
                flash(user_msg, 'danger')
                return None
            elif response.status == 401:
                fmt_action = str(action).lower()
                fmt_resource = str(resource).lower()
                user_msg = 'You are not authorized to {} {}.'.format(fmt_action, fmt_resource)
                flash(user_msg, 'warning')
                return None
            elif response.status >= 400:
                user_msg = 'Exception occured while contacting backend, please try again later.'
                flash(user_msg, 'danger')
            return response.data

    def handle(self):
        """
        Override this method with view function
        """
        raise NotImplementedError

    def kqueen_request(self, resource, action, fnargs=(), fnkwargs={}, service=False):
        client = self._get_kqueen_service_client() if service else self._get_kqueen_client()
        if not client:
            return None
        try:
            manager = getattr(client, resource)
            response = getattr(manager, action)(*fnargs, **fnkwargs)
        except AttributeError:
            msg = 'Unknown API method reference "{}.{}"'.format(resource, action)
            self.logger('error', msg)
            return None
        except TypeError:
            msg = 'Invalid API method arguments; args: {}, kwargs: {}'.format(str(fnargs), str(fnkwargs))
            self.logger('error', msg)
            return None
        return self._handle_response(response)

    def logger(self, severity, message):
        view = self.__class__.__name__
        msg = '{} view: {}'.format(view, message)
        logger_fn = getattr(logger, severity)
        logger_fn(msg)

    def dispatch_request(self):
        return self.handle()
