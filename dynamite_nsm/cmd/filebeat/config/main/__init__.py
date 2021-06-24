from dynamite_nsm.services.filebeat import config
from dynamite_nsm.utilities import get_environment_file_dict
from dynamite_nsm.cmd.service_interfaces import SimpleConfigManagerInterface

env_vars = get_environment_file_dict()

try:
    interface = \
        SimpleConfigManagerInterface(config.ConfigManager(env_vars['FILEBEAT_HOME']),
                                     interface_name='Filebeat Configuration',
                                     interface_description='Configure various Filebeat config options.',
                                     defaults=dict(install_directory=env_vars['FILEBEAT_HOME'], stdout=True)
                                     )
except KeyError:
    interface = None
except FileNotFoundError:
    interface = None

"""
if not interface:
    print(f'Skipping filebeat.config.main as it was never retrieved successfully')
"""