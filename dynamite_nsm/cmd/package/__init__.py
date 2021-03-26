import argparse
from dynamite_nsm.cmd.package import saved_objects
from dynamite_nsm.utilities import get_primary_ip_address
from dynamite_nsm.cmd.interface_operations import append_service_interface_to_parser


def get_action_parser():
    parser = argparse.ArgumentParser(description=f'Kibana Saved Objects Manager @ {get_primary_ip_address()}')
    subparsers = parser.add_subparsers()
    append_service_interface_to_parser(subparsers, 'saved_objects', saved_objects.interface, interface_group_name='interface')
    return parser


def get_interfaces():
    return dict(
        saved_objects=saved_objects.interface,
    )
