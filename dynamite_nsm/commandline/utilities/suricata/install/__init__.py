from dynamite_nsm.commandline.service_to_commandline import SingleResponsibilityInterface
from dynamite_nsm.services.suricata import install

interface = \
    SingleResponsibilityInterface(cls=install.InstallManager,
                                  interface_name='Suricata',
                                  interface_description='Install Suricata as a standalone component.',
                                  entry_method_name='setup',
                                  defaults=dict(download_suricata_archive=True,
                                                install_directory='/opt/dynamite/suricata',
                                                configuration_directory='/etc/dynamite/suricata',
                                                log_directory='/opt/dynamite/suricata/logs',
                                                stdout=True,
                                                )
                                  )
