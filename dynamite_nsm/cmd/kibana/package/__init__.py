from dynamite_nsm.cmd.service_interfaces import MultipleResponsibilityInterface
from dynamite_nsm.services.kibana import package

interface = \
    MultipleResponsibilityInterface(cls=package.SavedObjectsManager,
                                    supported_method_names=["install",
                                                            "uninstall", "list",
                                                            'list_saved_objects',
                                                            'list_tenants'],
                                    interface_name='Kibana Package Manager',
                                    interface_description='Add, remove, and manage packages '
                                                          'created for Dynamite Kibana.',
                                    defaults=dict(stdout=True)
                                    )
