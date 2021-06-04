from dynamite_nsm.services.agent import install
from dynamite_nsm.cmd.service_interfaces import SingleResponsibilityInterface

interface = \
    SingleResponsibilityInterface(cls=install.UninstallManager,
                                  interface_name='Agent Uninstall Manager',
                                  interface_description='Uninstall all the agent components on this machine.',
                                  entry_method_name='uninstall',
                                  defaults=dict(purge_config=False, stdout=True)
                                  )
