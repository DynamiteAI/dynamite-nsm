from dynamite_nsm import utilities
from dynamite_nsm.services.remote import install
from dynamite_nsm.cmd.service_interfaces import SingleResponsibilityInterface

interface = \
    SingleResponsibilityInterface(cls=install.InstallManager,
                                  interface_name='Remotes Install Manager',
                                  interface_description='Install a remote manager authentication package.',
                                  entry_method_name='setup',
                                  defaults=dict(install_directory='/opt/dynamite/remotes', stdout=True)
                                  )
