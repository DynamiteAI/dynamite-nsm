from dynamite_nsm.service_to_commandline import SingleResponsibilityInterface
from dynamite_nsm.services.zeek import install

interface = \
    SingleResponsibilityInterface(cls=install.UninstallManager,
                                  interface_name='Zeek Uninstall',
                                  interface_description='Uninstall Zeek on this machine.',
                                  entry_method_name='uninstall',
                                  defaults=dict(purge_config=False, stdout=True)
                                  )
