from kqueen_ui.api import KQueenAPIClient

client = KQueenAPIClient('admin', 'default')
_list = client.cluster.list()
cluster_uuid = 'c88b05d6-a107-4636-a3cc-eb5c90562f8f'
_get = client.cluster.get(cluster_uuid)

print(_get)

