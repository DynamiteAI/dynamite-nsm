from dynamite_nsm.services.kibana import install
from dynamite_nsm.cmd.service_interfaces import SingleResponsibilityInterface

interface = \
    SingleResponsibilityInterface(cls=install.InstallManager,
                                  interface_name='Kibana Install Manager',
                                  interface_description='Install Kibana as a standalone component.',
                                  entry_method_name='setup',
                                  defaults=dict(download_kibana_archive=True,
                                                install_directory='/opt/dynamite/kibana',
                                                configuration_directory='/etc/dynamite/kibana',
                                                log_directory='/var/log/dynamite/kibana',
                                                stdout=True
                                                )
                                  )

