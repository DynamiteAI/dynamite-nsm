from dynamite_nsm.services.elasticsearch import config
from dynamite_nsm.utilities import get_environment_file_dict
from dynamite_nsm.cmd.service_interfaces import SimpleConfigManagerInterface

env_vars = get_environment_file_dict()
try:
    interface = \
        SimpleConfigManagerInterface(config.JavaHeapOptionsConfigManager(env_vars['ES_PATH_CONF']),
                                     interface_name='Elasticsearch Java Heap Configuration',
                                     interface_description='Configure Java heap allocation for Elasticsearch on '
                                                           'this machine.',
                                     defaults=dict(elasticsearch_jvm_config_path=env_vars['ES_PATH_CONF'],
                                                   configuration_directory=env_vars['ES_PATH_CONF'], stdout=True)
                                     )
except KeyError:
    interface = None
except FileNotFoundError:
    interface = None
"""
if not interface:
    print(f'Skipping elastic.config.java as it was never retrieved successfully')
"""