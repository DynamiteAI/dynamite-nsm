from dynamite_nsm.services.setup import install
from dynamite_nsm.cmd.service_interfaces import SingleResponsibilityInterface

interface = \
    SingleResponsibilityInterface(cls=install.InstallManager,
                                  interface_name='Dynamite Install Manager',
                                  interface_description='Setup required files and directories.',
                                  entry_method_name='setup',
                                  defaults=dict(stdout=True)
                                  )

