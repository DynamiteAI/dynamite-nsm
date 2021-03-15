from dynamite_nsm.commandline.service_to_commandline import SingleResponsibilityInterface
from dynamite_nsm.services.zeek import logs

interface = \
    SingleResponsibilityInterface(cls=logs.StatusLog,
                                  interface_name='Zeek Status Log',
                                  interface_description='View Zeek logs and statistics',
                                  entry_method_name='tail',
                                  )

