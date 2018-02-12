from flask import flash, session
from flask.views import View
from kqueen_ui.api import get_kqueen_client, get_service_client
from kqueen_ui.exceptions import KQueenAPIException
from uuid import UUID

import logging

logger = logging.getLogger('kqueen')


class KQueenView(View):
    """
    KQueen UI base view with methods to handle backend API calls.
    """
    validation_hint = None

    def _get_kqueen_client(self):
        token = session.get('user', {}).get('token', None)
        if token:
            return get_kqueen_client(token=token)
        return None

    def _get_kqueen_service_client(self):
        return get_service_client()

    def _handle_response(self, response, resource, action):
        if response is not None:
            msg = 'Status Code: {}; Data: {}'.format(str(response.status), str(response.data))
            if response.status == -1:
                user_msg = 'Backend is unavailable at this time, please try again later.'
                self.graceful_exit(msg, user_msg)
            elif response.status == 401:
                fmt_action = str(action).lower()
                fmt_resource = str(resource).lower()
                user_msg = 'You are not authorized to {} {}.'.format(fmt_action, fmt_resource)
                self.graceful_exit(msg, user_msg)
            elif response.status == 404:
                fmt_resource = str(resource).capitalize()
                user_msg = '{} not found.'.format(fmt_resource)
                self.graceful_exit(msg, user_msg)
            elif response.status >= 400:
                user_msg = 'Error occurred while contacting backend, please try again later.'
                self.graceful_exit(msg, user_msg)
            return response.data

    def _validate_uuid(self, uuid):
        try:
            UUID(uuid, version=4)
        except ValueError:
            msg = 'Invalid UUID {}'.format(str(uuid))
            self.logger('error', msg)
            flash(msg, 'warning')
            raise KQueenAPIException()

    def dispatch_request(self, *args, **kwargs):
        """
        Main method called by Flask on each request
        """
        self.validate(**kwargs)
        return self.handle(*args, **kwargs)

    def graceful_exit(self, logger_message, user_message=''):
        self.logger('error', logger_message)
        if user_message:
            flash(user_message, 'danger')
        raise KQueenAPIException()

    def handle(self):
        """
        Override this method with view function
        """
        raise NotImplementedError

    def kqueen_request(self, resource, action, fnargs=(), fnkwargs={}, service=False):
        client = self._get_kqueen_service_client() if service else self._get_kqueen_client()
        if not client:
            return None
        user_msg = 'Error occurred while contacting backend, please try again later.'
        # identify correct API method
        try:
            manager = getattr(client, resource)
            method = getattr(manager, action)
        except AttributeError:
            msg = 'Unknown API method reference "{}.{}"'.format(resource, action)
            self.graceful_exit(msg, user_msg)
        except Exception as e:
            msg = 'Unknown error during backend API request'
            self.graceful_exit(msg, user_msg)
        # call API method with provided args/kwargs
        try:
            response = method(*fnargs, **fnkwargs)
        except TypeError:
            msg = 'Invalid API method arguments; args: {}, kwargs: {}'.format(str(fnargs), str(fnkwargs))
            self.graceful_exit(msg, user_msg)
        except Exception as e:
            msg = 'Unknown error during backend API request'
            self.graceful_exit(msg, user_msg)
        return self._handle_response(response, resource, action)

    def logger(self, severity, message):
        view = self.__class__.__name__
        msg = '{} view: {}'.format(view, message)
        severity_map = {
            'critical': 50,
            'error': 40,
            'warning': 30,
            'info': 20,
            'debug': 10
        }
        logger.log(severity_map[severity], msg, exc_info=True)

    def validate(self, **kwargs):
        if self.validation_hint:
            if self.validation_hint == 'uuid':
                for kwarg in kwargs.values():
                    self._validate_uuid(kwarg)
