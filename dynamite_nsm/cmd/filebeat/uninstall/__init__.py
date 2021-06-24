from dynamite_nsm.services.filebeat import install
from dynamite_nsm.cmd.service_interfaces import SingleResponsibilityInterface

interface = \
    SingleResponsibilityInterface(cls=install.UninstallManager,
                                  interface_name='Filebeat Uninstall Manager',
                                  interface_description='Uninstall Filebeat on this machine.',
                                  entry_method_name='uninstall',
                                  defaults=dict(purge_config=True, stdout=True)
                                  )
