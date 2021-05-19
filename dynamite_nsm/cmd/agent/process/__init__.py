from dynamite_nsm.services.agent import process
from dynamite_nsm.cmd.service_interfaces import MultipleResponsibilityInterface

interface = \
    MultipleResponsibilityInterface(cls=process.ProcessManager,
                                    interface_name='Agent Process(es) Manager',
                                    interface_description='Manage local Agent processes.',
                                    supported_method_names=['start', 'stop', 'restart', 'status'],
                                    defaults=dict(pretty_print_status=True, stdout=True)
                                    )
