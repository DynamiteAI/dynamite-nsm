from dynamite_nsm.services.auth import install
from dynamite_nsm.cmd.service_interfaces import SingleResponsibilityInterface

interface = \
    SingleResponsibilityInterface(cls=install.InstallManager,
                                  interface_name='Auth Package Install Manager',
                                  interface_description='Install a remote manager authentication package.',
                                  entry_method_name='setup',
                                  defaults=dict(install_directory='/opt/dynamite/remotes', stdout=True)
                                  )
