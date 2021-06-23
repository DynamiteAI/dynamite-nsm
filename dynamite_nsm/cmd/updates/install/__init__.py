from dynamite_nsm import const
from dynamite_nsm.services.updates import install
from dynamite_nsm.cmd.service_interfaces import SingleResponsibilityInterface

interface = \
    SingleResponsibilityInterface(cls=install.InstallManager,
                                  interface_name='Update DynamiteNSM Default Configs',
                                  interface_description='Update mirrors and default configurations',
                                  entry_method_name='setup',
                                  defaults=dict(stdout=True, url=const.DEFAULT_CONFIGURATIONS_URL)
                                  )
