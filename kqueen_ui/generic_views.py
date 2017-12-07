from flask import abort, flash, redirect, request, session
from flask.views import View
from kqueen_ui.api import get_kqueen_client, get_service_client
from kqueen_ui.exceptions import KQueenAPIException
from uuid import UUID

import logging

logger = logging.getLogger(__name__)


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
            if response.status == -1:
                msg = 'Backend is unavailable at this time, please try again later.'
                flash(msg, 'danger')
                raise KQueenAPIException()
            elif response.status == 401:
                fmt_action = str(action).lower()
                fmt_resource = str(resource).lower()
                msg = 'You are not authorized to {} {}.'.format(fmt_action, fmt_resource)
                flash(msg, 'warning')
                raise KQueenAPIException()
            elif response.status == 404:
                fmt_resource = str(resource).capitalize()
                msg = '{} not found.'.format(fmt_resource)
                flash(msg, 'warning')
                raise KQueenAPIException()
            elif response.status >= 400:
                msg = 'Exception occured while contacting backend, please try again later.'
                flash(msg, 'danger')
                raise KQueenAPIException()
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
            abort(500)
        except TypeError:
            msg = 'Invalid API method arguments; args: {}, kwargs: {}'.format(str(fnargs), str(fnkwargs))
            self.logger('error', msg)
            abort(500)
        return self._handle_response(response, resource, action)

    def logger(self, severity, message):
        view = self.__class__.__name__
        msg = '{} view: {}'.format(view, message)
        logger_fn = getattr(logger, severity)
        logger_fn(msg)

    def validate(self, **kwargs):
        if self.validation_hint:
            if self.validation_hint == 'uuid':
                for kwarg in kwargs.values():
                    self._validate_uuid(kwarg)
