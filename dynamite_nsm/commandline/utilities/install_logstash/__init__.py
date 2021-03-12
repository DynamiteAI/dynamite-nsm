from dynamite_nsm.commandline.service_to_commandline import SingleResponsibilityInterface
from dynamite_nsm.services.logstash import install

interface = \
    SingleResponsibilityInterface(cls=install.InstallManager,
                                  interface_name='Logstash Installer',
                                  interface_description='Install Logstash as a standalone component.',
                                  entry_method_name='setup',
                                  defaults=dict(download_logstash_archive=True,
                                                install_directory='/opt/dynamite/logstash',
                                                configuration_directory='/etc/dynamite/logstash',
                                                log_directory='/var/log/dynamite/logstash',
                                                stdout=True,
                                                )
                                  )

