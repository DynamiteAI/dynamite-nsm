from dynamite_nsm.services.zeek import logs
from dynamite_nsm.cmd.service_interfaces import SingleResponsibilityInterface

interface = \
    SingleResponsibilityInterface(cls=logs.BrokerLog,
                                  interface_name='Zeek Broker Log',
                                  interface_description='Peering status events between Zeek or Broker-enabled processes',
                                  defaults=dict(log_sample_size=500),
                                  entry_method_name='tail',
                                  )

