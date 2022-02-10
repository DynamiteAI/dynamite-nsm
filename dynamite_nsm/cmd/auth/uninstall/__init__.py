from dynamite_nsm.cmd.service_interfaces import SingleResponsibilityInterface
from dynamite_nsm.services.auth import install

interface = \
    SingleResponsibilityInterface(cls=install.UninstallManager,
                                  interface_name='Auth Package Uninstall Manager',
                                  interface_description='Uninstall a remote manager authentication package.',
                                  entry_method_name='uninstall',
                                  defaults=dict(purge_config=False, stdout=True)
                                  )
