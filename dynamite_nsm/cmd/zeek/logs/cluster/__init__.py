from dynamite_nsm.cmd.service_interfaces import SingleResponsibilityInterface
from dynamite_nsm.services.zeek import logs

interface = \
    SingleResponsibilityInterface(cls=logs.ClusterLog,
                                  interface_name='Zeek Cluster Log',
                                  interface_description='View Zeek connections between nodes within this Zeek cluster.',
                                  defaults=dict(log_sample_size=500),
                                  entry_method_name='tail',
                                  )

