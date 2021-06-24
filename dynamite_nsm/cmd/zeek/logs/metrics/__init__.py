from dynamite_nsm.cmd.service_interfaces import SingleResponsibilityInterface
from dynamite_nsm.services.zeek import logs

interface = \
    SingleResponsibilityInterface(cls=logs.StatusLog,
                                  interface_name='Zeek Aggregated Metrics',
                                  interface_description='Zeek metrics aggregated over a consistent time interval.',
                                  defaults=dict(log_sample_size=500),
                                  entry_method_name='tail',
                                  )

