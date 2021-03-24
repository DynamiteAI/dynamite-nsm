from dynamite_nsm.services.suricata import logs
from dynamite_nsm.cmd.service_interfaces import SingleResponsibilityInterface

interface = \
    SingleResponsibilityInterface(cls=logs.MainLog,
                                  interface_name='Suricata Main Log',
                                  interface_description='View Suricata Internal error/warning/info messages.',
                                  defaults=dict(log_sample_size=500),
                                  entry_method_name='tail',
                                  )

