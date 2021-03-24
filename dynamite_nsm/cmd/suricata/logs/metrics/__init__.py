from dynamite_nsm.services.suricata import logs
from dynamite_nsm.cmd.service_interfaces import SingleResponsibilityInterface

interface = \
    SingleResponsibilityInterface(cls=logs.StatsLog,
                                  interface_name='Suricata Aggregated Metrics',
                                  interface_description='Suricata metrics aggregated over a consistent time interval.',
                                  defaults=dict(log_sample_size=10000),
                                  entry_method_name='tail',
                                  )

