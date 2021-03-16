from dynamite_nsm.services.logstash import process
from dynamite_nsm.service_to_commandline import MultipleResponsibilityInterface

interface = \
    MultipleResponsibilityInterface(cls=process.ProcessManager,
                                    interface_name='Logstash',
                                    interface_description='Manage local Logstash instance.',
                                    supported_method_names=['start', 'stop', 'restart', 'status'],
                                    defaults=dict(pretty_print_status=True, stdout=True)
                                    )
