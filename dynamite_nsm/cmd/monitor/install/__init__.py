from dynamite_nsm.services.monitor import install
from dynamite_nsm.cmd.service_interfaces import SingleResponsibilityInterface

interface = \
    SingleResponsibilityInterface(cls=install.InstallManager,
                                  interface_name='Monitor Install Manager',
                                  interface_description='Install monitor components and configure this system to '
                                                        'receive events and alerts from various agents.',
                                  entry_method_name='setup',
                                  defaults=dict(stdout=True,
                                                elasticsearch_install_directory='/opt/dynamite/elasticsearch/',
                                                elasticsearch_configuration_directory='/etc/dynamite/elasticsearch/',
                                                elasticsearch_log_directory='/var/log/dynamite/elasticsearch/',
                                                # As of DynamiteNSM 1.0 we do not setup logstash as part of the
                                                # monitor installation, unless this option is explicitly enabled by
                                                # the end-user agents (by default) will send events directly to
                                                # elasticsearch
                                                logstash_install_directory=None,
                                                logstash_configuration_directory=None,
                                                logstash_log_directory=None,
                                                kibana_install_directory='/opt/dynamite/kibana/',
                                                kibana_configuration_directory='/etc/dynamite/kibana/',
                                                kibana_log_directory='/var/log/dynamite/kibana/'
                                                )
                                  )
