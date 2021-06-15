from dynamite_nsm.services.zeek import config
from dynamite_nsm.utilities import get_environment_file_dict
from dynamite_nsm.cmd.service_interfaces import SimpleConfigManagerInterface

env_vars = get_environment_file_dict()

try:
    interface = \
        SimpleConfigManagerInterface(config.SiteLocalConfigManager(env_vars['ZEEK_SCRIPTS']),
                                     interface_name='Zeek Scripts Configuration',
                                     interface_description='Configure which Zeek scripts are enabled/disabled.',
                                     defaults=dict(configuration_directory=env_vars['ZEEK_SCRIPTS'], stdout=True)
                                     )
except KeyError:
    interface = None
except FileNotFoundError:
    interface = None

"""
if not interface:
    print(f'Skipping zeek.config.scripts as it was never retrieved successfully')
"""
