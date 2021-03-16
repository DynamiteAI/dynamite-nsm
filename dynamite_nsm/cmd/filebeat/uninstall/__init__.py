from dynamite_nsm.service_to_commandline import SingleResponsibilityInterface
from dynamite_nsm.services.filebeat import install

interface = \
    SingleResponsibilityInterface(cls=install.UninstallManager,
                                  interface_name='Filebeat Uninstall',
                                  interface_description='Uninstall Filebeat on this machine.',
                                  entry_method_name='uninstall',
                                  defaults=dict(purge_config=False, stdout=True)
                                  )
