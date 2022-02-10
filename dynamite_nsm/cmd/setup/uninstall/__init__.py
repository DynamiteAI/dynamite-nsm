from dynamite_nsm.cmd.service_interfaces import SingleResponsibilityInterface
from dynamite_nsm.services.setup import install

interface = \
    SingleResponsibilityInterface(cls=install.UninstallManager,
                                  interface_name='DynamiteNSM Uninstall Manager',
                                  interface_description='Uninstall DynamiteNSM on this machine.',
                                  entry_method_name='uninstall',
                                  )
