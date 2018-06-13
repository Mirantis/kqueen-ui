from datetime import datetime
from dateutil.parser import parse as dateutil_parse
from flask import current_app as app
from flask_babel import to_utc
from functools import reduce
from urllib.parse import urlencode, urljoin

import json
import logging
import urllib3
import six

logger = logging.getLogger('kqueen_ui')
http = urllib3.PoolManager()


class KQueenResponse:
    status = 200
    error = ''
    data = {}

    def __iter__(self):
        for item in self.data:
            yield item

    def __len__(self):
        return len(self.data)

    def __getitem__(self, x):
        return self.data[x]

    def get(self, item, default=None):
        if default:
            return self.data.get(item, default)
        else:
            return self.data.get(item)


class ParserMixin:
    DATETIME_FIELDS = ['created_at']

    def _parse_response_datetime(self, _dict):
        for key, value in _dict.items():
            if key in self.DATETIME_FIELDS and value:
                _dict[key] = dateutil_parse(value)
            elif isinstance(value, dict):
                self._parse_response_datetime(value)
            elif isinstance(value, list):
                self._parse_response(value)

    def _parse_request_payload_datetime(self, _dict):
        for key, value in _dict.items():
            if key in self.DATETIME_FIELDS:
                if isinstance(value, datetime):
                    _dict[key] = value.isoformat()
                elif isinstance(value, six.string_types):
                    fmt_dt = dateutil_parse(value)
                    dt = to_utc(fmt_dt)
                    _dict[key] = dt.isoformat()
            elif isinstance(value, dict):
                self._parse_request_payload_datetime(value)

    def _parse_response(self, response):
        if isinstance(response, list):
            for item in response:
                self._parse_response(item)
        elif isinstance(response, dict):
            self._parse_response_datetime(response)
        return response

    def _parse_request_payload(self, payload):
        if isinstance(payload, list):
            for item in payload:
                self._parse_request_payload_datetime(item)
        elif isinstance(payload, dict):
            self._parse_request_payload_datetime(payload)
        return payload


class BaseManager(ParserMixin):
    resource_url = ''

    def __init__(self, client):
        self.client = client

    def login(self):
        payload = json.dumps({
            'username': self.client.username,
            'password': self.client.password
        })

        r = self._request('', override_url=self.client.auth_url, method='POST', payload=payload, auth=False)
        token = r.data.get('access_token', None)
        error = None
        self.client.token = token
        if r.error:
            try:
                _msg = json.loads(r.error)
                msg = _msg['description']
            except Exception:
                msg = r.error
            error = {
                'status': r.status,
                'description': msg
            }
            logger.warning('KQueen Client:: Could not get access token: {}'.format(r.error))
        return token, error

    def _request(self, url_suffix, method='GET', payload=None, override_url=None, encode_kw=None, auth=True):
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }

        if auth:
            headers['Authorization'] = 'Bearer %s' % self.client.token

        _url = reduce(urljoin, [self.client.base_url, self.resource_url, url_suffix])
        url = _url[:-1] if _url.endswith('/') else _url
        if override_url:
            url = override_url
        if encode_kw:
            url = url + '?' + urlencode(encode_kw)

        body = None
        if method in ['POST', 'PATCH']:
            if isinstance(payload, dict):
                parsed_payload = self._parse_request_payload(payload)
                body = json.dumps(parsed_payload)
            else:
                body = payload

        response = KQueenResponse()

        try:
            raw = http.request(method, url, body=body, headers=headers)
        except Exception as e:
            response.error = repr(e)
            response.status = -1
            logger.exception('KQueen Client:: {}'.format(repr(e)))
            return response

        response.status = raw.status

        if response.status > 200:
            response.error = raw.data.decode('utf-8')
            logger.error('KQueen Client:: {}'.format(raw.data.decode('utf-8')))
            return response

        try:
            data = json.loads(raw.data.decode('utf-8'))
            response.data = self._parse_response(data)
        except json.decoder.JSONDecodeError as e:
            response.error = 'JSONDecodeError: {}'.format(repr(e))
            logger.exception('KQueen Client: {}'.format(response.error))

        return response

    def request(self, *args, **kwargs):
        if not self.client.token:
            self.login()
        return self._request(*args, **kwargs)

    def list(self, namespace=None, all_namespaces=None):
        encode_kw = None
        if all_namespaces:
            encode_kw = {
                'all_namespaces': True
            }
        elif namespace:
            encode_kw = {
                'namespace': namespace
            }
        return self.request('', encode_kw=encode_kw)

    def get(self, uuid):
        return self.request(uuid)

    def create(self, payload):
        return self.request('', method='POST', payload=payload)

    def delete(self, uuid):
        return self.request(uuid, method='DELETE')

    def update(self, uuid, payload):
        return self.request(uuid, method='PATCH', payload=payload)


class ClusterManager(BaseManager):
    resource_url = 'clusters/'

    def status(self, uuid):
        return self.request('%s/status' % uuid)

    def topology_data(self, uuid):
        return self.request('%s/topology-data' % uuid)

    def kubeconfig(self, uuid):
        return self.request('%s/kubeconfig' % uuid)

    def progress(self, uuid):
        return self.request('%s/progress' % uuid)

    def resize(self, uuid, node_count):
        payload = {
            'node_count': node_count
        }
        return self.request('%s/resize' % uuid, method='PATCH', payload=payload)

    def set_network_policy(self, uuid, enabled, provider='CALICO'):
        payload = {
            'provider': provider,
            'enabled': enabled
        }
        return self.request('%s/set_network_policy' % uuid, method='PATCH', payload=payload)

    def list(self, namespace=None, all_namespaces=None, page=1, per_page=20):
        encode_kw = {'offset': (page - 1) * per_page, 'limit': per_page} if page else {}
        if all_namespaces:
            encode_kw['all_namespaces'] = True
        elif namespace:
            encode_kw['namespace'] = namespace
        return self.request('', encode_kw=encode_kw)

    def health(self, namespace=None, all_namespaces=None):
        encode_kw = None
        if all_namespaces:
            encode_kw = {'all_namespaces': True}
        elif namespace:
            encode_kw = {'namespace': namespace}
        return self.request('health', encode_kw=encode_kw)


class ProvisionerManager(BaseManager):
    resource_url = 'provisioners/'

    def engines(self):
        return self.request('engines')

    def list(self, namespace=None, all_namespaces=None, page=1, per_page=20):
        encode_kw = {'offset': (page - 1) * per_page, 'limit': per_page} if page else {}
        if all_namespaces:
            encode_kw['all_namespaces'] = True
        elif namespace:
            encode_kw['namespace'] = namespace
        return self.request('', encode_kw=encode_kw)

    def health(self, namespace=None, all_namespaces=None):
        encode_kw = None
        if all_namespaces:
            encode_kw = {'all_namespaces': True}
        elif namespace:
            encode_kw = {'namespace': namespace}
        return self.request('health', encode_kw=encode_kw)


class OrganizationManager(BaseManager):
    resource_url = 'organizations/'

    def deletable(self, uuid):
        return self.request('%s/deletable' % uuid, method='GET')

    def policy(self, uuid):
        return self.request('%s/policy' % uuid, method='GET')


class UserManager(BaseManager):
    resource_url = 'users/'

    def updatepw(self, uuid, payload):
        return self.request('%s/updatepw' % uuid, method='PATCH', payload=payload)

    def update(self, uuid, payload):
        organization = payload.get('organization', None)
        if organization and isinstance(organization, dict):
            payload['organization'] = 'Organization:{}'.format(payload['organization']['id'])
        return self.request(uuid, method='PATCH', payload=payload)

    def whoami(self):
        return self.request('whoami')


class ConfigurationManager(BaseManager):
    resource_url = 'configurations/'

    def auth(self):
        return self.request('auth')


class KQueenAPIClient:

    def __init__(
        self,
        username=None,
        password=None,
        token=None,
        base_url='http://localhost:5000/api/v1/',
        auth_url='http://localhost:5000/api/v1/auth'
    ):
        # Save credentials
        self.username = username
        self.password = password
        self.token = token
        self.base_url = base_url
        self.auth_url = auth_url
        # Register managers
        self.base = BaseManager(self)
        self.cluster = ClusterManager(self)
        self.provisioner = ProvisionerManager(self)
        self.organization = OrganizationManager(self)
        self.user = UserManager(self)
        self.configuration = ConfigurationManager(self)


def get_kqueen_client(username=None, password=None, token=None):
    base_url = app.config['KQUEEN_API_URL']
    auth_url = app.config['KQUEEN_AUTH_URL']
    return KQueenAPIClient(username, password, token, base_url, auth_url)


def get_service_client():
    username = app.config['KQUEEN_SERVICE_USER_USERNAME']
    password = app.config['KQUEEN_SERVICE_USER_PASSWORD']
    return get_kqueen_client(username=username, password=password)
