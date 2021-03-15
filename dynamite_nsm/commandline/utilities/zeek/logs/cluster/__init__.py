from dynamite_nsm.commandline.service_to_commandline import SingleResponsibilityInterface
from dynamite_nsm.services.zeek import logs

interface = \
    SingleResponsibilityInterface(cls=logs.ClusterLog,
                                  interface_name='Zeek Cluster Log',
                                  interface_description='View Zeek connections between nodes within this Zeek cluster.',
                                  entry_method_name='tail',
                                  )

