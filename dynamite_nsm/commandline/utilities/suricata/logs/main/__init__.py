from dynamite_nsm.commandline.service_to_commandline import SingleResponsibilityInterface
from dynamite_nsm.services.suricata import logs

interface = \
    SingleResponsibilityInterface(cls=logs.MainLog,
                                  interface_name='Suricata Main Log',
                                  interface_description='View Suricata Internal error/warning/info messages.',
                                  defaults=dict(log_sample_size=500),
                                  entry_method_name='tail',
                                  )

