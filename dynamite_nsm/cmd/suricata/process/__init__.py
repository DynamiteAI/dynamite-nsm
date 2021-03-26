from dynamite_nsm.cmd.service_interfaces import MultipleResponsibilityInterface
from dynamite_nsm.services.suricata import process

interface = \
    MultipleResponsibilityInterface(cls=process.ProcessManager,
                                    interface_name='Suricata Process Manager',
                                    interface_description='Manage local Suricata node processes.',
                                    supported_method_names=['start', 'stop', 'restart', 'status'],
                                    defaults=dict(pretty_print_status=True, stdout=True)
                                    )