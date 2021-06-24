from dynamite_nsm.services.suricata import config
from dynamite_nsm.utilities import get_environment_file_dict
from dynamite_nsm.cmd.service_interfaces import SimpleConfigManagerInterface

env_vars = get_environment_file_dict()

try:
    interface = \
        SimpleConfigManagerInterface(config.ConfigManager(env_vars['SURICATA_CONFIG']),
                                     interface_name='Suricata Configuration',
                                     interface_description='Configure various Suricata config options.',
                                     defaults=dict(configuration_directory=env_vars['SURICATA_CONFIG'], stdout=True)
                                     )
except KeyError:
    interface = None
except FileNotFoundError:
    interface = None
"""
if not interface:
    print(f'Skipping suricata.config.main as it was never retrieved successfully')
"""