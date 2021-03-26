
import argparse
from dynamite_nsm.utilities import get_primary_ip_address
from dynamite_nsm.cmd.interface_operations import append_service_interface_to_parser
from dynamite_nsm.services.kibana import package
from dynamite_nsm.cmd.service_interfaces import MultipleResponsibilityInterface

interface = \
    MultipleResponsibilityInterface(cls=package.SavedObjectsManager,
                                  supported_method_names=["add", "remove", "list"],
                                  interface_name='Kibana Saved Objects Manager',
                                  interface_description='Add, remove and manage Saved Objects in Kibana',
                                  defaults=dict()
                                  )


