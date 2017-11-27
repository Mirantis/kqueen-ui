DEBUG = True

# External endpoint
SERVER_NAME = 'localhost:8000'

# App secret
SECRET_KEY = 'secret'
SECURITY_PASSWORD_SALT = 'secret_salt'

# KQueen API
KQUEEN_API_URL = 'http://localhost:5000/api/v1/'
KQUEEN_AUTH_URL = 'http://localhost:5000/api/v1/auth'

# Babel
BABEL_DEFAULT_TIMEZONE = 'UTC'
BABEL_DEFAULT_LOCALE = 'en'

# Registration
ENABLE_PUBLIC_REGISTRATION = True
KQUEEN_SERVICE_USER_NAME = 'admin'
KQUEEN_SERVICE_USER_PASSWORD = 'default'

# Mail
MAIL_SERVER = 'localhost'
MAIL_PORT = 25
MAIL_USE_TLS = False
MAIL_USE_SSL = False
MAIL_USERNAME = None
MAIL_PASSWORD = None
MAIL_DEFAULT_SENDER = 'kqueen@mirantis.com'
MAIL_MAX_EMAILS = None
MAIL_ASCII_ATTACHMENTS = False

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
