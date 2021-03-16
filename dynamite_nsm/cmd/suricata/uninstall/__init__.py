from dynamite_nsm.service_to_commandline import SingleResponsibilityInterface
from dynamite_nsm.services.suricata import install

interface = \
    SingleResponsibilityInterface(cls=install.UninstallManager,
                                  interface_name='Suricata Uninstall',
                                  interface_description='Uninstall Suricata this machine.',
                                  entry_method_name='uninstall',
                                  defaults=dict(purge_config=False, stdout=True)
                                  )
