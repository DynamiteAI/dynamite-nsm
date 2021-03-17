from dynamite_nsm.service_to_commandline import SimpleConfigManagerInterface
from dynamite_nsm.services.elasticsearch import config
from dynamite_nsm.utilities import get_environment_file_dict

env_vars = get_environment_file_dict()

interface = \
    SimpleConfigManagerInterface(config.ConfigManager(env_vars['ES_PATH_CONF']),
                           interface_name='Elasticsearch Configuration',
                           interface_description='Configure Elasticsearch on this machine.',
                           defaults=dict(configuration_directory=env_vars['ES_PATH_CONF'], stdout=True)
                           )
