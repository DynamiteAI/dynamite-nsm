from dynamite_nsm.commandline.service_to_commandline import MultipleResponsibilityInterface
from dynamite_nsm.services.kibana import process

interface = \
    MultipleResponsibilityInterface(cls=process.ProcessManager,
                                    interface_name='Kibana',
                                    interface_description='Manage local Kibana node processes.',
                                    supported_method_names=['start', 'stop', 'restart', 'status'],
                                    defaults=dict(pretty_print_status=True, stdout=True)
                                    )
