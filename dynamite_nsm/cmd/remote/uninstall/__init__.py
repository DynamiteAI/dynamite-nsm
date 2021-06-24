from dynamite_nsm.cmd.service_interfaces import SingleResponsibilityInterface
from dynamite_nsm.services.remote import install

interface = \
    SingleResponsibilityInterface(cls=install.UninstallManager,
                                  interface_name='Dynamite Remote Node Uninstall Manager',
                                  interface_description='Uninstall Dynamite Remote Node on this machine.',
                                  entry_method_name='uninstall',
                                  defaults=dict(purge_config=False, stdout=True)
                                  )
