from dynamite_nsm.commandline.service_to_commandline import SingleResponsibilityInterface
from dynamite_nsm.services.zeek import logs

interface = \
    SingleResponsibilityInterface(cls=logs.BrokerLog,
                                  interface_name='Zeek Broker Log',
                                  interface_description='Peering status events between Zeek or Broker-enabled processes',
                                  entry_method_name='tail',
                                  )

