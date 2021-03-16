from dynamite_nsm.commandline.service_to_commandline import SingleResponsibilityInterface
from dynamite_nsm.services.zeek import logs

interface = \
    SingleResponsibilityInterface(cls=logs.ReporterLog,
                                  interface_name='Zeek Reporter Log',
                                  interface_description='View Zeek Internal error/warning/info messages.',
                                  defaults=dict(log_sample_size=500),
                                  entry_method_name='tail',
                                  )

