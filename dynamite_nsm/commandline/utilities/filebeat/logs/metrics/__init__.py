from dynamite_nsm.commandline.service_to_commandline import SingleResponsibilityInterface
from dynamite_nsm.services.filebeat import logs

interface = \
    SingleResponsibilityInterface(cls=logs.StatusLog,
                                  interface_name='Filebeat Aggregated Metrics',
                                  interface_description='Filebeat metrics aggregated over a consistent time interval.',
                                  defaults=dict(log_sample_size=500),
                                  entry_method_name='tail_metrics',
                                  )

