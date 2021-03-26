from dynamite_nsm.services.logstash import install
from dynamite_nsm.cmd.service_interfaces import SingleResponsibilityInterface

interface = \
    SingleResponsibilityInterface(cls=install.InstallManager,
                                  interface_name='Logstash Install Manager',
                                  interface_description='Install Logstash as a standalone component.',
                                  entry_method_name='setup',
                                  defaults=dict(download_logstash_archive=True,
                                                install_directory='/opt/dynamite/logstash',
                                                configuration_directory='/etc/dynamite/logstash',
                                                log_directory='/var/log/dynamite/logstash',
                                                stdout=True,
                                                )
                                  )

