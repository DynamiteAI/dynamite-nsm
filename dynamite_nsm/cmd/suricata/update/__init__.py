from dynamite_nsm.services.suricata import update
from dynamite_nsm.cmd.service_interfaces import SingleResponsibilityInterface

interface = \
    SingleResponsibilityInterface(cls=update.RuleUpdateManager,
                                  interface_name='Update Suricata Rules',
                                  interface_description='Install the latest Suricata rule-sets.',
                                  entry_method_name='update',
                                  defaults=dict(stdout=True)
                                  )
