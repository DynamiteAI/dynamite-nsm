import argparse

from dynamite_nsm.cmd.filebeat.logs import main, metrics
from dynamite_nsm.utilities import get_primary_ip_address
from dynamite_nsm.cmd.interface_operations import append_service_interface_to_parser


def get_action_parser():
    parser = argparse.ArgumentParser(description=f'Filebeat @ {get_primary_ip_address()}')
    subparsers = parser.add_subparsers()
    append_service_interface_to_parser(subparsers, 'main', main.interface, interface_group_name='sub_interface')
    append_service_interface_to_parser(subparsers, 'metrics', metrics.interface, interface_group_name='sub_interface')
    return parser


def get_interfaces():
    return dict(
        main=main.interface,
        metrics=metrics.interface,
    )
