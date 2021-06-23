from dynamite_nsm.cmd.service_interfaces import SingleResponsibilityInterface
from dynamite_nsm.services.zeek import install

interface = \
    SingleResponsibilityInterface(cls=install.UninstallManager,
                                  interface_name='Zeek Uninstall Manager',
                                  interface_description='Uninstall Zeek on this machine.',
                                  entry_method_name='uninstall',
                                  defaults=dict(purge_config=True, stdout=True)
                                  )
