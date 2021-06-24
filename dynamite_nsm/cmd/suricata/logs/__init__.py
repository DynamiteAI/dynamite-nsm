import argparse

from dynamite_nsm.cmd.suricata.logs import main, metrics
from dynamite_nsm.cmd.interface_operations import append_service_interface_to_parser


def get_action_parser():
    parser = argparse.ArgumentParser(description=f'Suricata Log Manager')
    subparsers = parser.add_subparsers()
    append_service_interface_to_parser(subparsers, 'main', main.interface, interface_group_name='sub_interface')
    append_service_interface_to_parser(subparsers, 'metrics', metrics.interface, interface_group_name='sub_interface')
    return parser


def get_interfaces():
    return dict(
        main=main.interface,
        metrics=metrics.interface,
    )
