from dynamite_nsm.services.suricata import install
from dynamite_nsm.cmd.service_interfaces import SingleResponsibilityInterface

interface = \
    SingleResponsibilityInterface(cls=install.InstallManager,
                                  interface_name='Suricata Install Manager',
                                  interface_description='Install Suricata as a standalone component.',
                                  entry_method_name='setup',
                                  defaults=dict(download_suricata_archive=True,
                                                install_directory='/opt/dynamite/suricata',
                                                configuration_directory='/etc/dynamite/suricata',
                                                log_directory='/opt/dynamite/suricata/logs',
                                                stdout=True,
                                                )
                                  )
