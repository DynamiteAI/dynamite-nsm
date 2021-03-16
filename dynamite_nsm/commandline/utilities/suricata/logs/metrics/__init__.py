from dynamite_nsm.commandline.service_to_commandline import SingleResponsibilityInterface
from dynamite_nsm.services.suricata import logs

interface = \
    SingleResponsibilityInterface(cls=logs.StatsLog,
                                  interface_name='Suricata Aggregated Metrics',
                                  interface_description='Suricata metrics aggregated over a consistent time interval.',
                                  defaults=dict(log_sample_size=10000),
                                  entry_method_name='tail',
                                  )

