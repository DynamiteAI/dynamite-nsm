from dynamite_nsm.services.agent import optimize
from dynamite_nsm.cmd.service_interfaces import SingleResponsibilityInterface

interface = \
    SingleResponsibilityInterface(cls=optimize.OptimizeThreadingManager,
                                  interface_name='Agent Optimization Manager',
                                  interface_description='Automatically adjust how resources are allocated between '
                                                        'Zeek and Suricata.',
                                  entry_method_name='optimize',
                                  defaults=dict(stdout=True, suricata_configuration_directory='/etc/dynamite/suricata/',
                                                zeek_install_directory='/opt/dynamite/zeek/')
                                  )
