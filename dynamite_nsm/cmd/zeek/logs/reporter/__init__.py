from dynamite_nsm.services.zeek import logs
from dynamite_nsm.cmd.service_interfaces import SingleResponsibilityInterface

interface = \
    SingleResponsibilityInterface(cls=logs.ReporterLog,
                                  interface_name='Zeek Reporter Log',
                                  interface_description='View Zeek Internal error/warning/info messages.',
                                  defaults=dict(log_sample_size=500),
                                  entry_method_name='tail',
                                  )

