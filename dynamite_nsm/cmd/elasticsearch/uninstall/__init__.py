from dynamite_nsm.services.elasticsearch import install
from dynamite_nsm.cmd.service_interfaces import SingleResponsibilityInterface

interface = \
    SingleResponsibilityInterface(cls=install.UninstallManager,
                                  interface_name='Elasticsearch Uninstall Manager',
                                  interface_description='Uninstall Elasticsearch on this machine.',
                                  entry_method_name='uninstall',
                                  defaults=dict(purge_config=True, stdout=True)
                                  )
