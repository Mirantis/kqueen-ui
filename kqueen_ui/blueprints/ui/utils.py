from collections import OrderedDict
from flask_babel import format_datetime
from kqueen_ui.api import get_kqueen_client
from kqueen_ui.config import current_config

try:
    from secrets import choice
except ImportError:
    from random import choice

import string

config = current_config()


def status_for_cluster_detail(_status):
    status = {}
    # Check Helm Tiller status
    status['tiller'] = -1
    podcount = 0
    images = []

    _persistent_volumes = {}
    if 'persistent_volumes' in _status:
        for pv in _status['persistent_volumes']:
            pv_storage_class = pv['spec'].pop('storage_class_name', '-')
            pv_host_path = pv['spec'].pop('host_path', '-')
            pv_capacity = pv['spec'].pop('capacity', {}).get('storage', '-')
            pv_access_modes = ', '.join(pv['spec'].pop('access_modes', []))
            pv_reclaim_policy = pv['spec'].pop('persistent_volume_reclaim_policy', '-')
            pv_claim_ref = pv['spec'].pop('claim_ref', {})
            # deduce storage driver from the remaining spec keys
            pv_driver = {
                'name': '-',
                'metadata': {}
            }
            for spec_name, spec in pv['spec'].items():
                if spec and isinstance(spec, dict):
                    pv_driver['name'] = spec_name
                    pv_driver['metadata'] = spec
            pv_name = pv['metadata']['name']
            pv_creation_timestamp = pv['metadata']['creation_timestamp']
            pv_deletion_timestamp = pv['metadata']['deletion_timestamp']
            pv_status = pv['status']['phase']
            _persistent_volumes[pv_name] = {
                'storage_class': pv_storage_class,
                'host_path': pv_host_path or '-',
                'capacity': pv_capacity,
                'access_modes': pv_access_modes,
                'reclaim_policy': pv_reclaim_policy,
                'claim_ref': pv_claim_ref,
                'driver': pv_driver,
                'name': pv_name,
                'creation_timestamp': pv_creation_timestamp,
                'deletion_timestamp': pv_deletion_timestamp or '-',
                'status': pv_status
            }

    persistent_volume_claims = []
    if 'persistent_volume_claims' in _status:
        for pvc in _status['persistent_volume_claims']:
            pvc_requested_capacity = pvc['spec'].get('resources', {}).get('requests', {}).get('storage', '-')
            pvc_storage_class = pvc['spec']['storage_class_name']
            pvc_access_modes = ', '.join(pvc['spec'].get('access_modes', []))
            pvc_name = pvc['metadata']['name']
            pvc_namespace = pvc['metadata']['namespace']
            pvc_creation_timestamp = pvc['metadata']['creation_timestamp']
            pvc_deletion_timestamp = pvc['metadata']['deletion_timestamp']
            pvc_status = pvc['status']['phase']
            # deduce related volume
            pvc_volume = {}
            volume_name = pvc['spec']['volume_name']
            if volume_name:
                pvc_volume = _persistent_volumes.pop(volume_name, {})
            persistent_volume_claims.append({
                'requested_capacity': pvc_requested_capacity,
                'storage_class': pvc_storage_class,
                'access_modes': pvc_access_modes,
                'name': pvc_name,
                'namespace': pvc_namespace,
                'creation_timestamp': pvc_creation_timestamp,
                'deletion_timestamp': pvc_deletion_timestamp or '-',
                'status': pvc_status,
                'volume': pvc_volume
            })
        status['persistent_volume_claims'] = persistent_volume_claims

    persistent_volumes = []
    for name, volume in _persistent_volumes.items():
        volume['name'] = name
        persistent_volumes.append(volume)
    status['persistent_volumes'] = persistent_volumes

    nodes = []
    if 'nodes' in _status:
        for node in _status['nodes']:
            node_name = node['metadata']['name']
            excluded_addr_types = ['LegacyHostIP', 'InternalDNS', 'ExternalDNS', 'Hostname']
            node_ip = [
                a['type'] + ': ' + a['address']
                for a in node['status']['addresses']
                if a['type'] not in excluded_addr_types
            ]
            node_os = {
                'os': node['status']['node_info']['os_image'],
                'kernel': node['status']['node_info']['kernel_version']
            }
            node_status = []
            for sc in node['status']['conditions']:
                if sc['type'] != 'Ready':
                    if sc['status'] == 'False':
                        icon = 'mdi-checkbox-marked-circle-outline'
                    else:
                        icon = 'mdi-close-circle-outline'
                    node_status.append({
                        'type': sc['type'],
                        'icon': icon
                    })
            _ram = int(node['status']['allocatable']['memory'].replace('Ki', '')) / 1000000
            ram = '{:.2f}'.format(_ram)
            cpu = node['status']['allocatable']['cpu']
            node_size = cpu + '/' + ram
            pods = int(_status.get('nodes_pods', {}).get(node['metadata']['name']))
            podcount += pods
            maxpods = int(node['status']['allocatable']['pods'])
            percentage = (pods / maxpods) * 100
            node_pods = {
                'pods': pods,
                'maxpods': maxpods,
                'percentage': percentage
            }

            for image in node['status']['images']:
                image['names'] = tuple(image['names'])
                mib_size = int(image['size_bytes']) / 1024 / 1024
                image['size_bytes'] = '{:.2f} MiB'.format(mib_size)
            images.extend(node['status']['images'])

            nodes.append({
                'name': node_name,
                'ip': node_ip,
                'os': node_os,
                'status': node_status,
                'size': node_size,
                'pods': node_pods,
            })
    status['nodes'] = nodes
    # filter out duplicate images and sort them by verbose name
    images_set = set([tuple(d.items()) for d in images])
    images_sorted = sorted(list(images_set), key=lambda k: [i for i in k if 'names' in i][0][1][-1])
    status['images'] = [OrderedDict(t) for t in images_sorted]

    deployments = []
    if 'deployments' in _status:
        for deployment in _status['deployments']:
            deployment_name = deployment['metadata']['name']
            deployment_namespace = deployment['metadata']['namespace']
            _ready = deployment.get('status', {}).get('ready_replicas', '0')
            ready = int(_ready) if _ready else 0
            _desired = deployment.get('spec', {}).get('replicas', '0')
            desired = int(_desired) if _desired else 0
            percentage = 0
            if desired > 0:
                percentage = (ready / desired) * 100
            deployment_replicas = {
                'ready': ready,
                'desired': desired,
                'percentage': percentage
            }
            containers = deployment.get('spec', {}).get('template', {}).get('spec', {}).get('containers', [])
            deployment_containers = [
                {
                    'name': c['name'],
                    'image': c['image']
                }
                for c
                in containers
            ]
            deployments.append({
                'name': deployment_name,
                'namespace': deployment_namespace,
                'replicas': deployment_replicas,
                'containers': deployment_containers
            })
            # Check for Helm Tiller status here, while we are iteration over deployments anyways
            if deployment_namespace == 'kube-system' and deployment_name == 'tiller-deploy':
                _available = deployment.get('status', {}).get('ready_replicas', '0')
                status['tiller'] = int(_available) if _available else 0
    status['deployments'] = deployments

    services = []
    if 'services' in _status:
        for service in _status['services']:
            service_name = service['metadata']['name']
            service_namespace = service['metadata']['namespace']
            service_cluster_ip = service['spec']['cluster_ip']
            _ports = service.get('spec', {}).get('ports', [])
            ports = _ports or []
            service_ports = [
                '%s/%s %s' % (p['port'], p['protocol'], p.get('name', ''))
                for p
                in ports
            ]
            ingress = service.get('status', {}).get('load_balancer', {}).get('ingress', [])
            service_external_ip = []
            if ingress:
                for endpoint in ingress:
                    _port_map = {
                        80: 'http',
                        8080: 'http',
                        443: 'https',
                        4430: 'https',
                        6443: 'https'
                    }
                    hostname = endpoint.get('hostname', '')
                    if hostname:
                        for port in ports:
                            _port = port['port']
                            proto = _port_map[_port] if _port in _port_map else 'http'
                            service_external_ip.append('%s://%s:%s' % (proto, hostname, _port))
            services.append({
                'name': service_name,
                'namespace': service_namespace,
                'cluster_ip': service_cluster_ip,
                'ports': service_ports,
                'external_ip': service_external_ip
            })
    status['services'] = services

    status['addons'] = _status['addons'] if 'addons' in _status else []

    c_namespaces = len(_status.get('namespaces', []))
    c_nodes = len(status['nodes'])
    c_deployments = len(status['deployments'])
    c_services = len(status['services'])
    status['overview'] = {
        'namespaces': c_namespaces,
        'namespaces_max': c_namespaces if c_namespaces else 1,
        'nodes': c_nodes,
        'nodes_max': c_nodes if c_nodes else 1,
        'deployments': c_deployments,
        'deployments_max': c_deployments if c_deployments else 1,
        'pods': podcount,
        'pods_max': podcount if podcount else 1,
        'services': c_services,
        'services_max': c_services if c_services else 1
    }

    return status


def prettify_engine_name(engine):
    if '.' in engine:
        engine = engine.split('.')[-1]
    if engine.endswith('Engine'):
        engine = engine[:-6]
    return engine


def generate_password(length=20):
    alphabet = string.ascii_letters + string.digits
    return ''.join(choice(alphabet) for _ in range(length))


def sanitize_resource_metadata(session, clusters, provisioners):
    from kqueen_ui import cache

    token = session.get('user', {}).get('token', None)
    client = None
    engines = cache.get('provisioner-engines')
    deployed_clusters = 0
    healthy_clusters = 0
    healthy_provisioners = 0

    if not engines:
        abort = False
        if token:
            client = get_kqueen_client(token=token)
        else:
            abort = True
        if client:
            engines_res = client.provisioner.engines()
            if engines_res.status > 200:
                abort = True
            else:
                engines = engines_res.data
                cache.set('provisioner-engines', engines, timeout=5 * 60)
        if abort:
            for cluster in clusters:
                cluster['metadata'] = {}
            for provisioner in provisioners:
                provisioner['parameters'] = {}
            return clusters, provisioners

    for cluster in clusters:
        if 'state' in cluster:
            if config.get('CLUSTER_PROVISIONING_STATE') != cluster['state']:
                deployed_clusters = deployed_clusters + 1
            if cluster['state'] in [config.get('CLUSTER_RESIZING_STATE'), config.get('CLUSTER_OK_STATE')]:
                healthy_clusters = healthy_clusters + 1
        if 'created_at' in cluster:
            cluster['created_at'] = format_datetime(cluster['created_at'])

        cluster_engine = cluster.get('provisioner', {}).get('engine')
        _engine_params = [e['parameters'] for e in engines if e['name'] == cluster_engine]
        if not len(_engine_params) == 1:
            del cluster['metadata']
            continue
        engine_params = _engine_params[0].get('cluster')
        for param_name, param in engine_params.items():
            if param['type'] not in ['text', 'integer', 'select']:
                try:
                    cluster['metadata'][param_name] = '*****************'
                except KeyError:
                    pass
        cluster['metadata'] = OrderedDict(sorted(cluster['metadata'].items(), key=lambda t: t[0]))

    for provisioner in provisioners:
        if 'state' in provisioner:
            if config.get('PROVISIONER_ERROR_STATE') != provisioner['state']:
                healthy_provisioners = healthy_provisioners + 1
        if 'created_at' in provisioner:
            provisioner['created_at'] = format_datetime(provisioner['created_at'])

        provisioner_engine = provisioner.get('engine')
        _engine_params = [e['parameters'] for e in engines if e['name'] == provisioner_engine]
        if not len(_engine_params) == 1:
            del provisioner['parameters']
            continue
        engine_params = _engine_params[0].get('provisioner')
        for param_name, param in engine_params.items():
            if param['type'] not in ['text', 'integer', 'select']:
                try:
                    provisioner['parameters'][param_name] = '*****************'
                except KeyError:
                    pass
        provisioner['parameters'] = OrderedDict(sorted(provisioner['parameters'].items(), key=lambda t: t[0]))

    # sort clusters by date
    if isinstance(clusters, list):
        clusters.sort(key=lambda k: (k['created_at'], k['name']))

    # sort provisioners by date
    if isinstance(provisioners, list):
        provisioners.sort(key=lambda k: (k['created_at'], k['name']))

    cluster_health = 0
    if healthy_clusters and deployed_clusters:
        cluster_health = int((healthy_clusters / deployed_clusters) * 100)
    provisioner_health = 0
    if healthy_provisioners and provisioners:
        provisioner_health = int((healthy_provisioners / len(provisioners)) * 100)

    overview = {
        'cluster_count': len(clusters),
        'cluster_max': len(clusters) if len(clusters) else 1,
        'cluster_health': cluster_health,
        'provisioner_count': len(provisioners),
        'provisioner_max': len(provisioners) if len(provisioners) else 1,
        'provisioner_health': provisioner_health,
    }

    return clusters, provisioners, overview
