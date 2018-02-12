import os
import yaml
import logging.config
import logging
import coloredlogs

def setup_logging(default_path='/code/kqueen_ui/utils/logger_config.yml', default_level=logging.INFO, env_key='LOG_CFG'):

    path = os.getenv(env_key, default_path)

    if os.path.exists(path):
        with open(path, 'rt') as f:
            try:
                config = yaml.safe_load(f.read())
                logging.config.dictConfig(config)
                coloredlogs.install()
            except Exception as e:
                print(e)
                print('Failed to load configuration file.\
                      Using default configs. Kqueen generic logging, user logging will not work properly')
                logging.basicConfig(level=default_level)
                coloredlogs.install(level=default_level)
    else:
        logging.basicConfig(level=default_level)
        coloredlogs.install(level=default_level)
        print('Failed to load configuration file.\
              Using default configs. Kqueen generic logging, user logging will not work properly')



# Import user data from flask session to provide user_logging
def user_prefix(session):
    user_prefix = '[USER: {} ID:{}]'.format(session['user']['username'], session['user']['id'])
    return user_prefix
