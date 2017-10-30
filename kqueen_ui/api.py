from functools import reduce
from urllib.parse import urljoin

import json
import logging
import urllib3

logger = logging.getLogger(__name__)
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


class BaseManager:
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

    def _request(self, url_suffix, method='GET', payload=None, override_url=None, auth=True):
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }

        if auth:
            headers['Authorization'] = 'JWT %s' % self.client.token

        _url = reduce(urljoin, [self.client.base_url, self.resource_url, url_suffix])
        url = _url[:-1] if _url.endswith('/') else _url
        if override_url:
            url = override_url

        body = None
        if method in ['POST', 'CREATE']:
            if isinstance(payload, dict):
                body = json.dumps(payload)
            else:
                body = payload

        response = KQueenResponse()

        try:
            raw = http.request(method, url, body=body, headers=headers)
        except Exception as e:
            response.error = repr(e)
            response.status = -1
            logger.error('KQueen Client:: {}'.format(repr(e)))
            return response

        response.status = raw.status

        if response.status > 200:
            response.error = raw.data.decode('utf-8')
            logger.error('KQueen Client:: {}'.format(raw.data.decode('utf-8')))
            return response

        try:
            response.data = json.loads(raw.data.decode('utf-8'))
        except json.decoder.JSONDecodeError as e:
            response.error = 'JSONDecodeError: {}'.format(repr(e))
            logger.error('KQueen Client:: {}'.format(repr(e)))

        return response

    def request(self, *args, **kwargs):
        if not self.client.token:
            self._login()
        return self._request(*args, **kwargs)

    def list(self):
        return self.request('')

    def get(self, uuid):
        return self.request(uuid)

    def create(self, payload):
        return self.request('', method='POST', payload=payload)

    def delete(self, uuid):
        return self.request(uuid, method='DELETE')


class ClusterManager(BaseManager):
    resource_url = 'clusters/'

    def status(self, uuid):
        return self.request('%s/status' % uuid)

    def topology_data(self, uuid):
        return self.request('%s/topology-data' % uuid)

    def kubeconfig(self, uuid):
        return self.request('%s/kubeconfig' % uuid)


class ProvisionerManager(BaseManager):
    resource_url = 'provisioners/'


class OrganizationManager(BaseManager):
    resource_url = 'organizations/'


class UserManager(BaseManager):
    resource_url = 'users/'


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
