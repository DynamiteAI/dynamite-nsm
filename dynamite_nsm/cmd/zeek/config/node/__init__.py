from dynamite_nsm.services.zeek import config
from dynamite_nsm.utilities import get_environment_file_dict
from dynamite_nsm.cmd.service_interfaces import SimpleConfigManagerInterface

env_vars = get_environment_file_dict()

try:
    interface = \
        SimpleConfigManagerInterface(config.NodeConfigManager(env_vars['ZEEK_HOME']),
                                     interface_name='Zeek Node Configuration',
                                     interface_description='Configure this local node your Zeek cluster.',
                                     defaults=dict(install_directory=env_vars['ZEEK_HOME'], stdout=True)
                                     )
except KeyError as e:
    interface = None
except FileNotFoundError:
    interface = None

"""
if not interface:
    print(f'Skipping zeek.config.scripts as it was never retrieved successfully')
"""
