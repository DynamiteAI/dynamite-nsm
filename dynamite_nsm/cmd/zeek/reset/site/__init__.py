from dynamite_nsm.services.zeek import config
from dynamite_nsm.utilities import get_environment_file_dict
from dynamite_nsm.cmd.service_interfaces import SingleResponsibilityInterface

env_vars = get_environment_file_dict()

try:
    interface = \
        SingleResponsibilityInterface(config.SiteLocalConfigManager,
                                      interface_name='Zeek Site Reset',
                                      interface_description='Reset Zeek\'s local site configuration back to its '
                                                            'install state.',
                                      defaults=dict(configuration_directory=env_vars['ZEEK_SCRIPTS'], stdout=True),
                                      entry_method_name='reset'
                                      )
except KeyError:
    interface = None
except FileNotFoundError:
    interface = None
