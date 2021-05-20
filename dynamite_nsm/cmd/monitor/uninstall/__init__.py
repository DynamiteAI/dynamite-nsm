from dynamite_nsm.services.monitor import install
from dynamite_nsm.cmd.service_interfaces import SingleResponsibilityInterface

interface = \
    SingleResponsibilityInterface(cls=install.UninstallManager,
                                  interface_name='Monitor Uninstall Manager',
                                  interface_description='Uninstall the monitor components on this machine.',
                                  entry_method_name='uninstall',
                                  defaults=dict(purge_config=False, stdout=True)
                                  )
