DEBUG = True

# App secret
SECRET_KEY = 'secret'
KQUEEN_API_URL = 'http://localhost:5000/api/v1/'
KQUEEN_AUTH_URL = 'http://localhost:5000/api/v1/auth'

# Cluster statuses
CLUSTER_ERROR_STATE = 'Error'
CLUSTER_OK_STATE = 'OK'
CLUSTER_PROVISIONING_STATE = 'Deploying'
CLUSTER_DEPROVISIONING_STATE = 'Destroying'
CLUSTER_UNKNOWN_STATE = 'Unknown'

# Provisioner statuses
PROVISIONER_ERROR_STATE = 'Error'
PROVISIONER_OK_STATE = 'OK'
PROVISIONER_UNKNOWN_STATE = 'Not Reachable'