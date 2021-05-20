from dynamite_nsm.services.monitor import process
from dynamite_nsm.cmd.service_interfaces import MultipleResponsibilityInterface

interface = \
    MultipleResponsibilityInterface(cls=process.ProcessManager,
                                    interface_name='Monitor Process(es) Manager',
                                    interface_description='Manage Local Monitor processes.',
                                    supported_method_names=['start', 'stop', 'restart', 'status'],
                                    defaults=dict(pretty_print_status=True, stdout=True)
                                    )
