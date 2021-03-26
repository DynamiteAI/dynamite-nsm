from dynamite_nsm.services.filebeat import logs
from dynamite_nsm.cmd.service_interfaces import SingleResponsibilityInterface

interface = \
    SingleResponsibilityInterface(cls=logs.StatusLog,
                                  interface_name='Filebeat Aggregated Metrics',
                                  interface_description='Filebeat metrics aggregated over a consistent time interval.',
                                  defaults=dict(log_sample_size=500),
                                  entry_method_name='tail_metrics',
                                  )

