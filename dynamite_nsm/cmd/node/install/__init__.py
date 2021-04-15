from dynamite_nsm import utilities
from dynamite_nsm.services.node import install
from dynamite_nsm.cmd.service_interfaces import SingleResponsibilityInterface

interface = \
    SingleResponsibilityInterface(cls=install.InstallManager,
                                  interface_name='Node Install Manager',
                                  interface_description='Install a DynamiteNSM node configuration so that this "node" '
                                                        'can be remotely managed.',
                                  entry_method_name='setup',
                                  defaults=dict(stdout=True, node_name=utilities.get_default_agent_tag(),
                                                host=utilities.get_primary_ip_address(), port=22)
                                  )
