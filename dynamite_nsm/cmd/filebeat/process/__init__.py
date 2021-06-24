from dynamite_nsm.services.filebeat import process
from dynamite_nsm.cmd.service_interfaces import MultipleResponsibilityInterface

interface = \
    MultipleResponsibilityInterface(cls=process.ProcessManager,
                                    interface_name='Filebeat Process Manager',
                                    interface_description='Manage local Filebeat processes.',
                                    supported_method_names=['start', 'stop', 'restart', 'status'],
                                    defaults=dict(pretty_print_status=True, stdout=True)
                                    )