from dynamite_nsm.service_to_commandline import MultipleResponsibilityInterface
from dynamite_nsm.services.zeek import process

interface = \
    MultipleResponsibilityInterface(cls=process.ProcessManager,
                                    interface_name='Zeek',
                                    interface_description='Manage local Zeek node processes.',
                                    supported_method_names=['start', 'stop', 'restart', 'status'],
                                    defaults=dict(pretty_print_status=True, stdout=True)
                                    )