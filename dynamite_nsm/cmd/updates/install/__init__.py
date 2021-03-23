from dynamite_nsm.services.updates import install
from dynamite_nsm.service_to_commandline import SingleResponsibilityInterface

interface = \
    SingleResponsibilityInterface(cls=install.InstallManager,
                                  interface_name='Updates',
                                  interface_description='Update mirrors and default configurations',
                                  entry_method_name='setup',
                                  defaults=dict(stdout=True)
                                  )
