from dynamite_nsm.services.agent import install
from dynamite_nsm.cmd.service_interfaces import SingleResponsibilityInterface

interface = \
    SingleResponsibilityInterface(cls=install.InstallManager,
                                  interface_name='Agent Install Manager',
                                  interface_description='Install agent components and configure this system as a '
                                                        'sensor.',
                                  entry_method_name='setup',
                                  defaults=dict(stdout=True,
                                                filebeat_install_directory='/opt/dynamite/filebeat',
                                                suricata_install_directory='/opt/dynamite/suricata/',
                                                suricata_configuration_directory='/etc/dynamite/suricata/',
                                                suricata_log_directory='/opt/dynamite/suricata/logs/',
                                                zeek_install_directory='/opt/dynamite/zeek/',
                                                zeek_configuration_directory='/etc/dynamite/zeek/',
                                                target_type='elasticsearch'
                                                )
                                  )
