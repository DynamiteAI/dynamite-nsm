from dynamite_nsm.services.kibana import install
from dynamite_nsm.cmd.service_interfaces import SingleResponsibilityInterface

interface = \
    SingleResponsibilityInterface(cls=install.UninstallManager,
                                  interface_name='Kibana Uninstall Manager',
                                  interface_description='Uninstall Kibana on this machine.',
                                  entry_method_name='uninstall',
                                  defaults=dict(purge_config=True, stdout=True)
                                  )
