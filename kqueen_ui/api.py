from functools import reduce
from urllib.parse import urljoin

import json
import logging
import urllib3

logger = logging.getLogger(__name__)
http = urllib3.PoolManager()


class BaseManager:
    resource_url = ''

    def __init__(self, client):
        self.client = client

    def _login(self):
        body = json.dumps({
            'username': self.client.username,
            'password': self.client.password
        })

        r = self._request('', override_url=self.client.auth_url, method='POST', body=body, auth=False)
        if r.get('access_token', None):
            self.client.token = r['access_token']
        else:
            logger.warning('KQueen Client:: Could not get access token')

    def _request(self, url_suffix, method='GET', body=None, override_url=None, auth=True):
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

        if method in ['POST', 'CREATE']:
            raw = http.request(method, url, body=body, headers=headers)
        else:
            raw = http.request(method, url, headers=headers)

        try:
            res = json.loads(raw.data.decode('utf-8'))
        except json.decoder.JSONDecodeError as e:
            res = None
            logger.error(repr(e))

        if raw.status == 401:
            logger.error('KQueen Client:: Unauthorized: %s' % res.get('description', ''))
            res = None

        return res

    def request(self, *args, **kwargs):
        if not self.client.token:
            self._login()
        return self._request(*args, **kwargs)

    def list(self):
        return self.request('') or []

    def get(self, uuid):
        return self.request(uuid) or {}

    def create(self, body):
        return self.request('', method='CREATE', body=body)

    def delete(self, uuid):
        return self.request(uuid, method='DELETE')


class ClusterManager(BaseManager):
    resource_url = 'clusters/'

    def status(self, uuid):
        return self.request('%s/status' % uuid) or {}

    def topology_data(self, uuid):
        return self.request('%s/topology-data' % uuid) or {}

    def kubeconfig(self, uuid):
        return self.request('%s/kubeconfig' % uuid) or {}


class ProvisionerManager(BaseManager):
    resource_url = 'provisioners/'


class OrganizationManager(BaseManager):
    resource_url = 'organizations/'


class UserManager(BaseManager):
    resource_url = 'users/'


class KQueenAPIClient:
    base_url = 'http://localhost:5000/api/v1/'
    auth_url = 'http://localhost:5000/api/v1/auth'

    def __init__(self, username=None, password=None, token=None):
        # Save credentials
        self.username = username
        self.password = password
        self.token = token
        # Register managers
        self.cluster = ClusterManager(self)
        self.provisioner = ProvisionerManager(self)
        self.organization = OrganizationManager(self)
        self.user = UserManager(self)
        # Call for token on any manager if there is no token
        if not self.token:
            self.cluster._login()
