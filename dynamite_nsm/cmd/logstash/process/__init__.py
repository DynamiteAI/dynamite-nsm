from dynamite_nsm.services.logstash import process
from dynamite_nsm.cmd.service_interfaces import MultipleResponsibilityInterface

interface = \
    MultipleResponsibilityInterface(cls=process.ProcessManager,
                                    interface_name='Logstash Process Manager',
                                    interface_description='Manage local Logstash instance.',
                                    supported_method_names=['start', 'stop', 'restart', 'status'],
                                    defaults=dict(pretty_print_status=True, stdout=True)
                                    )
