from dynamite_nsm.services.filebeat import config
from dynamite_nsm.utilities import get_environment_file_dict
from dynamite_nsm.cmd.service_interfaces import SingleResponsibilityInterface

env_vars = get_environment_file_dict()

try:
    interface = \
        SingleResponsibilityInterface(config.ConfigManager,
                                      interface_name='Filebeat Reset',
                                      interface_description='Reset Filebeat configuration back to its install state.',
                                      defaults=dict(install_directory=env_vars['FILEBEAT_HOME'], stdout=True),
                                      entry_method_name='reset'
                                      )
except KeyError:
    interface = None
except FileNotFoundError:
    interface = None
