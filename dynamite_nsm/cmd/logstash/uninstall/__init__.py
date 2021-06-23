from dynamite_nsm.cmd.service_interfaces import SingleResponsibilityInterface
from dynamite_nsm.services.logstash import install

interface = \
    SingleResponsibilityInterface(cls=install.UninstallManager,
                                  interface_name='Logstash Uninstall Manager',
                                  interface_description='Uninstall Logstash on this machine.',
                                  entry_method_name='uninstall',
                                  defaults=dict(purge_config=True, stdout=True)
                                  )
