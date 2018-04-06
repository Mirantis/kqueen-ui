import importlib
import logging
import os

CONFIG_FILE_DEFAULT = 'config/dev.py'
logger = logging.getLogger('kqueen_ui')


def apply_env_changes(config, prefix='KQUEENUI_'):
    """
    Read env variables starting with prefix and apply
    them to existing configuration

    Attributes:
        config (obj): Connfiguration object. This configuration will updated.
        prefix (str): Prefix for environment variables. Defaults to `KQUEENUI_`.

    """

    for name, value in os.environ.items():
        if name.startswith(prefix):
            config_key_name = name[len(prefix):]
            setattr(config, config_key_name, value)


def current_config():
    read_file = os.environ.get('KQUEEN_UI_CONFIG_FILE', CONFIG_FILE_DEFAULT)
    logger.debug('Loading config from {}'.format(read_file))

    module_name = read_file.replace('/', '.').replace('.py', '')

    module = importlib.import_module('kqueen_ui.{}'.format(module_name))
    config = getattr(module, 'Config')
    apply_env_changes(config)

    setattr(config, 'source_file', read_file)

    return config


kqueen_ui_config = current_config()
