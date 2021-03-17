from dynamite_nsm.service_to_commandline import SimpleConfigManagerInterface
from dynamite_nsm.services.logstash import config
from dynamite_nsm.utilities import get_environment_file_dict

env_vars = get_environment_file_dict()

interface = \
    SimpleConfigManagerInterface(config.JavaHeapOptionsConfigManager(env_vars['LS_PATH_CONF']),
                                 interface_name='Logstash Java Heap Configuration',
                                 interface_description='Configure Java heap allocation for Logstash on '
                                                       'this machine.',
                                 defaults=dict(logstash_jvm_config_path=env_vars['LS_PATH_CONF'],
                                               configuration_directory=env_vars['LS_PATH_CONF'], stdout=True)
                                 )
