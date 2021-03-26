from dynamite_nsm.services.zeek import install
from dynamite_nsm.cmd.service_interfaces import SingleResponsibilityInterface

interface = \
    SingleResponsibilityInterface(cls=install.InstallManager,
                                  interface_name='Zeek Install Manager',
                                  interface_description='Install Zeek as a standalone component.',
                                  entry_method_name='setup',
                                  defaults=dict(download_zeek_archive=True,
                                                install_directory='/opt/dynamite/zeek',
                                                configuration_directory='/etc/dynamite/zeek',
                                                stdout=True,
                                                )
                                  )
